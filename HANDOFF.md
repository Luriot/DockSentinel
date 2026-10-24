# DockSentinel handoff

Status: **user-friendly first-run onboarding, one-click local Docker detection, a Windows double-click
installer, CI test gating, finding triage/export, System Status/backups, a Community Applications–ready
Unraid template, native distribution, VS Code workflow and opt-in content scans implemented and verified
locally; changes are committed but not pushed or published.** The published image on GHCR predates this
iteration.
This document states exactly what exists, what was executed, and what remains.

Built on 2026-10-22/23 with Node.js 26.4.0, Trivy 0.75.0, Docker Desktop 4.96.2 (Linux Engine 29.9.2),
GitHub CLI 2.103.0 and Playwright/Chromium 156 on Windows. Docker and `gh` became available after the
initial implementation, so the image and live Docker integration were verified afterwards.

## What was implemented

### Docker environments

- Multiple endpoints with independent configuration and health: local Unix socket, plain TCP (explicitly
  marked insecure) and TCP with mutual TLS (CA, client certificate, client key, optional skip-verify).
- Add, edit, test, discover, enable/disable, scan-enable/disable and delete endpoints. Deletion is refused
  while a scan for that endpoint is queued or running.
- Read-only Docker API client: `_ping`, `/version`, `/containers/json?all=1`, `/images/json` and
  `/images/{id}/get` only. No container inspect, no environment variables, no filesystem access, no
  mutations, no shell/CLI.
- Discovery of running and stopped containers, image IDs, tags, repo digests, ports, state, network mode
  and timestamps. Only `docksentinel.*` labels are stored.
- Endpoint failures are isolated: an unreachable host marks only itself offline; discovery, scanning and
  alerting continue for the others.

### Image scanning

- Bundled Trivy in the production image; structured JSON only, never table parsing.
- Two genuinely different profiles:
  - **quick** — OS packages only, Java index skipped, 5-minute target.
  - **standard** — OS + language/application packages, 15-minute target.
- Images are exported from Docker by **immutable image ID**, then scanned via `trivy image --input`.
  The scanner never receives Docker credentials.
- Scanner and vulnerability-database versions/timestamps recorded per scan.
- Safe child-process execution: argument arrays, no shell, minimal environment, 15-minute hard timeout,
  96 MiB report cap, 8 GiB archive cap, 1 MiB stdout/64 KiB stderr caps, process-tree kill, abort support.
- Database-update failure retried once against the cached database with a warning; records DB age.
- Strict parsing: malformed/truncated output, empty reports, timeouts, non-zero exits and oversized
  reports all fail. They never look clean. Previous findings are preserved on failure.
- Retry with bounded exponential backoff for transient failures; one scan per environment at a time;
  configurable global concurrency; no overlapping scans for the same image.
- Recovery on restart: interrupted scans are requeued while budget remains, otherwise failed; scratch
  directories are cleaned.
- Manual scans from images/containers, scheduled scans, first-scan-on-discovery, and per-environment
  quick/standard intervals. Rescans happen even when the digest is unchanged, because vulnerability
  intelligence changes.

### Opt-in content scanning

- Separate manual scan type (`kind = content`) for Trivy's image config/content misconfiguration and secret
  scanners. Enabled per scanner in Settings; disabled by default.
- Runs `trivy image --input … --scanners misconfig,secret --image-config-scanners misconfig,secret` on the
  same exported archive. No vulnerability DB update, no vulnerability counts, no image scan-status changes,
  no alerts.
- Findings use a separate `content_findings` table and lifecycle/page. Only successful parsed content scans
  can resolve prior content findings.
- Secret handling: only rule ID, category, title, path, line range and severity are stored. Raw `Match`,
  code lines and layer contents are discarded; content-scan errors are generic and discard stderr.
- Misconfiguration coverage is image config (Dockerfile conversion) and IaC files inside the image only —
  explicitly not a host/daemon/running-container audit.

### Findings, prioritisation and exposure

- Findings normalised into a common model and tied to image ID, with mappings to every container,
  environment and host using that image.
- Lifecycle: open, resolved, reappeared (episode counter), severity/fix changes, append-only event history.
  Only a successful, successfully parsed scan can resolve a finding.
- Deduplicated image inventory by image ID; tags and digests retained for display and targets.
- Transparent priority tiers from severity, CISA KEV, fix availability, running state, exposure and
  workload criticality labels. No proprietary risk score.
- Optional CISA KEV sync (daily/manual) with last-known-data fallback and tri-state KEV status.
- Exposure classification: user-declared Internet exposure, potential exposure from published ports/host
  networking, no published ports, or unknown. Never claims a published port proves public reachability.
- Labels: `docksentinel.exposure`, `monitor`, `criticality`, `alert-min-severity`, `ignore-vulns`.

### Alerting

- ntfy adapter (self-hosted or ntfy.sh) with base URL, topic, optional Bearer token or basic auth,
  priority, tags, click link, Markdown messages and a test action.
- Alerts for new findings at/above threshold, resolved findings, newly available fixes, newly KEV-listed
  findings, final scan failures and (optional) stale results.
- Per-image grouping, dedupe keys, per-container thresholds/monitoring/ignore rules, retries at 1/5/15/60
  minutes, five attempts before failure, crash recovery for `sending` rows, full delivery history.
- Secrets encrypted at rest (AES-256-GCM), never returned by the API, never logged.

### Persistence, operations and security

- SQLite (WAL, foreign keys, strict tables) with append-only versioned migrations, indexes, explicit
  transactions, retention pruning and checkpointing.
- Single administrator, scrypt password hashing, hashed session tokens, 7-day sliding sessions,
  HttpOnly/SameSite=Strict/Secure-when-HTTPS cookies, CSRF header + Origin verification, login/setup rate
  limiting, setup token on first run, password change that invalidates other sessions.
- Structured logs with redaction, CSP and security headers, strict JSON-schema input validation, 512 KiB
  body limit, parameterised SQL, no arbitrary command execution.
- Health endpoint with DB check, graceful shutdown, bounded retries, endpoint isolation.
- Backup script (`VACUUM INTO` + key copy) and administrator password-reset script.
- Native launcher with per-user data folder, loopback default, actionable preflight errors, managed
  checksum-verified Trivy installer and Docker Desktop named-pipe support.
- One-click local Docker detection and creation (`GET /api/environments/detect`, `POST /api/environments/local`)
  plus a guided first-run Welcome screen and first-scan progress card.
- Windows double-click installer that installs a private checksum-verified Node.js runtime, builds the UI,
  installs verified Trivy and creates Desktop/Start Menu shortcuts.
- `.vscode/tasks.json` default compound task starts backend and Vite in parallel as background tasks.
- Navigation/UI labels simplified to Docker hosts, Scans, Alerts and a plain-language welcome/setup flow.

### Interface

- Dark, dense technical UI with nine views: Overview, Environments, Containers, Images, Vulnerabilities,
  Config & secrets, Scan activity, Notifications, Settings; plus login/setup and detail drawers.
- Severity is conveyed with text + shape, not colour alone; priority tiers show their factors; exposure is
  labelled carefully; failures, stale results and clean results are visually distinct.
- Search/filter/sort, pagination, loading/empty/error states, responsive layout (verified at 390 px),
  keyboard focus, skip link, dialog focus management, `aria-current`, captions and labels.
- No misleading charts or unsupported security scores.

## Supported scanners and Docker integrations

| Integration | Status |
| --- | --- |
| Trivy 0.75.0 image scan (`vuln` scanner) | Implemented and validated with the real binary |
| Docker Engine over Unix socket | Implemented; validated against a spec-shaped fake daemon and a real Docker Desktop Unix socket in the earlier container run |
| Docker Desktop named pipe (`//./pipe/docker_engine`) | Implemented and validated natively against Docker Desktop |
| Docker Engine over TCP (trusted network) | Implemented; validated against a fake daemon |
| Docker Engine over TCP with mutual TLS / optional skip-verify | Implemented; code path unit-typed but **not** exercised against a real TLS daemon |
| Remote hosts, Unraid Docker Engine, multiple endpoints | Implemented at the Docker API level; real-host validation pending |
| Additional scanners | Interface (`ScannerAdapter`) and normalisation boundary in place; no second scanner added |
| Opt-in Trivy image config/content scanning (misconfig + secret) | Implemented and validated with real Trivy; metadata-only secret storage; separate lifecycle/page |
| Runtime/host/daemon scanning | **Not implemented** (out of scope) |

Trivy coverage (OS packages, language packages, CVSS, fixes, references) and its limits are documented in
[`docs/SCANNERS.md`](docs/SCANNERS.md). DockSentinel does not implement any scanning logic itself.

## Architecture and technology choices

- **Node.js 24/26 + TypeScript executed natively** — no backend build step, no native modules. Node's
  built-in `node:sqlite`, `node:test` and type stripping keep the dependency surface small.
- **Fastify 5** — schema validation, hooks, static SPA serving, structured logging.
- **SQLite** (`node:sqlite`) — single-instance workload, zero external infrastructure, WAL with one writer.
- **React 19 + Vite + hand-written CSS** — 355 kB JS / 98 kB gzip, no component library.
- **No ORM, no cron library, no Docker SDK, no docker CLI** — explicit small modules instead.
- **Native launcher + verified Trivy installer** — Node 24 remains the prerequisite; Node SEA is still active
  development, so no self-contained executable is shipped.
- **Content scans use a separate `content_findings` table and page** — they never mix into vulnerability
  counters, alerts or image scan status. Secret values are dropped during parsing.
- **Trivy as a child process on a local image archive**, not as a privileged daemon client. Trade-off:
  temporary disk usage is bounded by `MAX_IMAGE_EXPORT_BYTES`; scanner isolation is stronger and TLS
  handling is uniform.
- **Modular monolith** with domain/repo/service/http boundaries; details in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## How to run and test locally

```bash
npm install
npm run dev                 # API plus the last built UI on :8080 (use dev:web for SPA hot reload)
npm run dev:web             # Vite on :5173, proxies /api to :8080
npm run native:setup        # build UI + install checksum-verified Trivy for native mode
npm run native              # native launcher on 127.0.0.1:8080
npm run typecheck
npm test                    # 82 unit + integration tests
npx playwright install chromium
npm run test:ui             # 14 browser tests
npm run build               # typecheck + production SPA
npm start                   # serves API + web/dist on :8080
```

VS Code: **Ctrl+Shift+B** runs `.vscode/tasks.json`'s default compound task (backend + Vite, parallel,
background). The underlying commands were started together and the Vite `/api` proxy was verified; the VS
Code CLI was not available to press the keybinding in this environment.

Real Trivy integration tests use the machine's normal Trivy cache when available and are skipped otherwise.
The tests do not need a Docker daemon: discovery/export use an in-process fake Docker HTTP server and the
scanner reads a deterministic synthetic `docker save` archive.

First run: obtain the setup token from the logs (or set `SETUP_TOKEN`), then open the UI, create the
administrator, add an endpoint and wait for discovery/scan.

## Production container verification (Docker Desktop, executed)

Commands used:

```bash
docker buildx build --platform linux/amd64 --load -t docksentinel:local .
docker run -d --name docksentinel-smoke -p 18080:8080 \
  -v docksentinel-smoke-data:/data \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e SETUP_TOKEN=smoke-test-token -e PUID=10001 -e PGID=0 docksentinel:local
```

`PGID=0` is Docker Desktop–specific: its Linux socket is `root:root` mode `0660`, while the application
process runs as UID 10001.

| Check | Observed |
| --- | --- |
| Dockerfile build + `buildx --check` | Build succeeded, no warnings |
| Container startup / health | Healthy; `/api/health` 200; bundled Trivy 0.75.0 detected; KEV synced (1754 entries) |
| Process privileges | `tini` as PID 1, application as UID 10001; data files owned by 10001 |
| Discovery | 2 live containers / 2 images, including DockSentinel itself |
| Real image scan | `nginx:1.19-alpine`: 96 findings (9 critical, 52 high, 29 medium, 6 low; 96 fixable); 14.4 s cold, 0.19 s warm |
| Re-scan stability | Same image: 96 open, **0 resolved/recreated**, target `image.tar (alpine 3.13.5)` |
| ntfy delivery | Test notification and grouped “9 critical, 52 high” alert delivered |
| Restart | 371 findings, 3 scans, 3 sent alerts and the authenticated session persisted |
| Graceful shutdown | `SIGTERM` handled; container exited 0 |
| Interrupted scan | Aborted by stop, requeued on start, completed with attempts=2; findings unchanged |
| UI against live data | Playwright login/navigation/screenshots succeeded (`test-results/screens/real-*.png`) |

This live run found one real bug that the fixture suite had missed: Trivy copies the `--input` path into
`Result.Target`, and the scan scratch directory is random, so re-scans produced different finding identities
(96 resolved + 96 appeared on an unchanged image). It was fixed by running Trivy from the scratch directory
with a relative archive name (plus a defensive prefix strip) and is covered by a new regression test.

## Actual results (executed, not assumed)

| Check | Result |
| --- | --- |
| `npm run typecheck` | Passed (strict, `noUnusedLocals`, backend + web) |
| `npm test` | **82/82 passing** in ~66 s |
| Node 24.12 compatibility | Full backend suite, typecheck, build and **14/14 UI tests** passed under Node 24.12.0; content identities now use JSON instead of embedded NULs |
| Real Trivy end-to-end test | Passed; synthetic Debian 11 image produced **61 findings** (3 critical, 10 high, 26 medium, 20 low, 2 unknown); failure-preservation and cleanup assertions passed |
| Docker discovery tests | Passed: 3 containers, 2 images, `0.0.0.0:8080` → potential exposure, declared label → confirmed, stopped → unknown, non-DockSentinel labels discarded, independent endpoint failure, only GET requests |
| Notification tests | Passed: one grouped alert per scan, dedupe, ntfy Bearer header, retry/backoff, test success/failure, disabled mode |
| KEV tests | Passed: sync, flagging, one alert, idempotent resync, failure retains last data |
| Scheduler tests | Passed: discovery, new-image queueing without duplication, quick vs standard due logic, stale alert once/day |
| Persistence/recovery tests | Passed: settings/session/inventory across restart, migrations idempotent, interrupted scans requeued/failed correctly |
| Security tests | Passed: 401/403/CSRF/Origin, SQL/XSS-shaped input, body limit, secret encryption and clearing, password change, no secret leakage; absolute-form and percent-encoded API auth bypass regression tests; login rechecks the hash after async verification |
| `vite build` | Passed: `index.html` 0.85 kB, CSS 26.18 kB (6.10 kB gzip), JS 386.84 kB (104.52 kB gzip) |
| `npm run test:ui` | **14/14 passing** (Chromium headless), screenshots captured under `test-results/screens` |
| Backup script + UI | Verified: consistent DB snapshot + key copy; System Status can create/list backups and stage a restore; startup applies the staged restore with a pre-restore copy |
| Finding triage/export | Verified: acknowledge/ignore/false-positive actions, suppression from default counts/alerts, CSV formula mitigation and JSON export |
| CI workflow | Added `.github/workflows/test.yml`; publish now has a reusable `test` job dependency. The follow-up CI run passed on Node 24.12 |
| Unraid/CA package | Canonical `templates/docksentinel.xml`, `ca_profile.xml`, 256px icon, support/project/readme metadata. Not yet submitted to Community Applications |
| Password reset script | Verified: new password accepted, old rejected, sessions invalidated |
| `npm audit` (prod and all) | 0 vulnerabilities at verification time |
| Workflow YAML | Parsed and executed successfully on the previous publication (run 39872718832); not re-run this iteration |
| Production image build | Passed on Docker Desktop (linux/amd64); `buildx --check` clean |
| Iteration image smoke | Built successfully; container healthy as UID 10001; content scan (4 findings) and vulnerability scan (85 findings) via a fake Docker endpoint; restart persistence and graceful stop verified. Real Docker discovery was validated natively via Docker Desktop's named pipe because Docker Desktop no longer exposes the Unix socket on this host |
| Live Docker discovery/scan | Passed against Docker Desktop 29.9.2; real nginx image, 96 findings; only GET API calls |
| Container lifecycle | Healthcheck, non-root app user, graceful SIGTERM exit 0, restart persistence, interrupted-scan requeue verified |
| Live ntfy delivery | Test + real finding alert received by a local receiver; dedupe/retry covered by tests |
| Native installer (Windows) | Passed with system Node and with portable Node: UI build, official Node 24.12/Trivy 0.75.0 downloads, SHA-256 verification, launcher creation, Desktop/Start Menu shortcuts |
| One-click onboarding | Passed in Chromium against real Docker Desktop: first-run setup, `Use Docker on this computer`, discovery, connected state, dashboard |
| Container onboarding | Final image built; one-click local host creation via `DOCKER_HOST` + fake Docker endpoint, discovery, graceful stop; app running as UID 10001 |
| Local Docker detection API | Passed: Windows named-pipe/Unix candidate selection and reachable/unreachable probing; one-click host creation/reuse integration test |
| Native launcher (Windows) | Passed: 127.0.0.1 default, health, first-run setup, data in appdata-style `DATA_DIR`, restart persistence, port-conflict guidance |
| Native + Docker Desktop | Passed via named pipe `//./pipe/docker_engine`: connection test, discovery, real scan with managed Trivy |
| Content scan (real Trivy) | Passed: image config + image content findings, secret metadata only, no raw values in DB/API, failure preserves prior content findings |
| VS Code task | JSON validated; both underlying commands ran together and the Vite proxy worked; keybinding not exercised without VS Code CLI |
| Arm64 build | **Not executed**; base images support arm64, workflow not run this iteration |

Screenshots from the UI test run (not committed): `test-results/screens/01-overview.png` … `09-setup-empty.png`.

## Security limitations and known gaps

- **No runtime protection.** No intrusion detection, process monitoring, WAF or live-compromise detection.
  An image can scan clean and still be exploited.
- **No guaranteed exposure detection.** Published ports and labels are signals. Firewalls, proxies, NAT and
  provider security groups are not inspected.
- **Scanner coverage is Trivy's coverage.** Scratch/distroless images without package metadata, vendored or
  statically linked code and missing metadata can be missed.
- Single administrator only: no users/roles, MFA or SSO.
- Login/setup rate limiting is in-memory and resets on restart.
- KEV data depends on the CISA feed; no signature verification beyond TLS, and stale data is marked rather
  than silently trusted.
- No per-action audit log beyond scans, finding events, alerts and request logs.
- Docker socket access is effectively host-root. The Compose file mounts it read-only, which does not make
  the API read-only. Prefer a socket group/socket proxy or TLS endpoints. Docker Desktop requires GID 0 for
  the socket; Linux/Unraid hosts use their socket's group.
- Docker Desktop's named pipe was exercised natively, and its Unix socket was exercised in the earlier
  container run. Mutual-TLS remote endpoints and an actual Unraid Docker Engine were **not** validated
  against real daemons.
- Image IDs are whatever `/images/json` reports. On containerd-backed engines this is the manifest digest,
  while Trivy reports the config digest; DockSentinel attributes by the requested image ID and documents
  the difference. The same image on differently-backed hosts may therefore be scanned twice.
- The scanner binary is trusted; replacing it on a custom image would defeat result integrity.
- The setup token is printed to logs once; protect log access.
- Backups contain encrypted secrets plus the key; they must be protected.
- Content scanning is not a host, daemon, Kubernetes or running-container audit. Image-content
  misconfiguration checks are useful only when IaC files are present. Secret scans can produce false
  positives and a clean result is not proof that an image has no credentials.
- Content findings are manual/opt-in and never generate alerts. Secret values are never stored, but the
  temporary Trivy report briefly contains them in the `0700` scratch directory before deletion.
- Native mode was executed on Windows only. macOS/Linux use the same Node code but their installer/launcher
  path was not executed. The Windows double-click installer was tested with system and portable Node; macOS/Linux
  still need Node.js 24.12+ and the command-line path.
- No SBOM export, no VEX, no automatic remediation, no container modification.
- Released under the MIT licence ([`LICENSE`](LICENSE)).

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model and hardening checklist.

## Configuring Docker endpoints and notifications

1. Read the setup token from the logs (or set `SETUP_TOKEN` before first start).
2. Environments → Add environment:
   - Linux/macOS local: kind `unix`, address `/var/run/docker.sock`.
   - Windows Docker Desktop: kind `unix`, address `//./pipe/docker_engine`.
   - Remote TLS: kind `tls`, address `host:2376`, paste CA/client cert/key.
   - Plain TCP only on a trusted private network.
3. Test connection, then Discover. The scheduler will queue a standard scan for new images.
4. Notifications → set ntfy base URL and topic, choose auth (`none`, token, basic), test delivery, enable,
   set the public base URL so notification links open this instance.
5. Settings → tune severity threshold, freshness, intervals, retention and KEV. Labels can refine policy
   per workload.

## Deployment, upgrades, backup and restore

- Production image: multi-stage `Dockerfile` (Node 24 slim runtime + pinned Trivy 0.75.0, CA certs, `tini`,
  `gosu`; app process drops to `PUID`/`PGID`). Compose example and Unraid template included.
- Native: `npm ci && npm run native:setup && npm run native`; data in the per-user application folder,
  managed Trivy installed and checksum-verified by `native:setup`. Node 24.12+ is required.
- Windows Docker Desktop named pipe is entered as kind `unix`, address `//./pipe/docker_engine`.
- Content scans: enable one or both scanners in Settings, then use **Content scan** in an image drawer.
  They are manual, separate from vulnerability scans, and never generate alerts.
- Upgrades: back up, pull/rebuild, restart. Migrations run automatically; downgrades are refused.
- Backup: `docker exec docksentinel node scripts/backup.ts` (`VACUUM INTO` + key copy).
- Restore: stop, replace `docksentinel.db` and `secret.key`, start.
- Full instructions, env var table, reverse proxy examples, socket permissions, remote TLS and
  troubleshooting: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`docs/UNRAID.md`](docs/UNRAID.md).

**Only the local Docker Desktop engine was used. No Unraid server or production credentials were contacted.**

## GHCR workflow status

- Repository: **public** — https://github.com/Luriot/DockSentinel (branch `main`).
- This iteration's commits are **local only**. The published image below still represents commit `4415f96`
  (before native/content changes); pushing this iteration would trigger a new publish and requires approval.
- Workflow: [`.github/workflows/publish.yml`](.github/workflows/publish.yml), triggered by pushes to
  `main`/`v*` tags that change image inputs, or by manual dispatch. Never by pull requests.
- Final successful run: https://github.com/Luriot/DockSentinel/actions/runs/39872718832
- Published manifest: `ghcr.io/luriot/docksentinel@sha256:b3d39f508a4aa8cf179c32b67dc8b97b24dd460616bb7dcb0a5c69a9abd3886c`
- Tags: `latest`, `main`, `sha-4415f96`
- Platforms: `linux/amd64`, `linux/arm64` (verified by the workflow and by an anonymous local pull).
- Supply chain: BuildKit **SBOM** and **maximum provenance** are attached to the image. The GitHub
  artifact attestation is signed with Sigstore, uploaded to Rekor and to the registry; it is guarded by
  repository visibility so a future private repository skips it instead of failing.
- Verification performed: anonymous `docker pull`, image labels (`licenses=MIT`, revision
  `4415f966…`, source repository), both platform manifests, and
  `gh attestation verify oci://ghcr.io/luriot/docksentinel:latest -R Luriot/DockSentinel` (exit 0).
- CI hygiene: actions are on their current Node 24 majors (`checkout@v7`, Docker actions
  `setup-qemu@v4`, `setup-buildx@v4`, `login@v4`, `metadata@v6`, `build-push@v7`,
  `attest-build-provenance@v4`) and the runner is pinned to `ubuntu-24.04`. The previous Node.js 20 and
  `ubuntu-latest` annotations are gone.
- The first run (private repository) failed only on GitHub's artifact-attestation API, which is not
  available for user-owned private repositories; BuildKit attestations and the image push had already
  succeeded. After making the repository public, the conditional step ran and the workflow is green.

## Exact actions still required from the user

1. **Approve push/publication** of this iteration. Pushing image-affecting changes to `main` triggers the
   publish workflow; no push or GHCR build was performed here.
2. **Remote Docker validation**: exercise a mutual-TLS endpoint and the real Unraid Docker Engine. Verify
   socket group IDs and update the Compose/template defaults if they differ from the documented guidance.
3. **Test native mode and shortcuts on macOS/Linux** (Windows installer/shortcut creation was tested; macOS/Linux
   still use the command-line path).
4. **Review the tag policy**: `latest`, `main` and `sha-<commit>` are published for the previous image. Create
   a `v*` tag when you want semver tags.
5. **Run the new CI workflow** on the first push; verify the reusable test job gates the publish job.
6. **Submit the prepared repository to Community Applications** at https://ca.unraid.net/submit/new with your Unraid forum account; approval is external to this repository.
7. Optionally add an arm64 runtime check and Windows code signing/service packaging.

## Notification providers (assessment only)

Current delivery is hard-wired to ntfy in `src/notify/ntfy.ts` and `NotificationDispatcher`; alerts already
store generic title/body/tags/priority/history. Easiest next providers, in order:

1. **Discord or Slack incoming webhook** — one JSON POST to an admin-configured webhook; reuse the stored
   alert body with size truncation. Estimated ~100–150 backend lines plus settings/UI/test.
2. **Gotify or Telegram** — similarly small HTTP integrations with a token/chat id.
3. **Generic webhook** — useful for automation, but it is admin-controlled SSRF by design; validate scheme
   and make it opt-in.
4. **SMTP email** — not a small change: Node has no SMTP client, formatting/attachments/TLS/bounce handling
   need a maintained library and more settings. Defer.

A small `NotificationProvider` interface and provider-specific settings would be needed before adding more
than one; ntfy-specific fields currently permeate settings, dispatcher validation and UI.

## Notable decisions and deviations

- The project was created in a new `DockSentinel` directory as requested; the prior empty `ScanGuard`
  directory is untouched.
- Scanning uses image export + `trivy --input` instead of giving Trivy Docker-daemon access. This is
  intentional for credential isolation and uniform TLS, and it is bounded by an export-size limit.
- The CISA KEV integration is a small JSON fetch into SQLite, because Trivy's image JSON does not include
  KEV membership. It is enrichment only and fails soft.
- The browser UI was tested both against seeded SQLite data and against the live container instance with
  real Docker findings. Backend integration tests use real Trivy with a synthetic image archive and a fake
  Docker API. A new UI test covers the content findings page.
- Native distribution deliberately keeps Node as a prerequisite instead of adopting Node SEA (Stability 1.1
  active development) or bundling a Node runtime. Trivy is downloaded from the official release and
  checksum-verified; the Docker image's pinned Trivy version is unchanged.
- Content scanning is manual and opt-in. It uses a separate table/page and no alerts, avoiding both
  vulnerability-data mixing and notification spam. Secret matching stores metadata only.
- First-run UX avoids asking normal users about socket kinds: it probes local Docker Desktop named pipes and
  Unix sockets and creates a host in one click. Manual connection remains available for remote/TLS hosts.
- The Windows installer installs a private Node.js runtime rather than requiring system Node; both Node and
  Trivy downloads are checksum-verified. It creates per-user shortcuts and opens the browser.
- The production Dockerfile was built and smoke-tested on Docker Desktop (linux/amd64). The linux/arm64
  build was not executed; the chosen base images publish arm64 manifests.
- Real Docker validation changed the result of the scanner integration: findings are now keyed by stable
  target names (`image.tar (alpine 3.13.5)`) instead of the random archive path, and Docker/Trivy image ID
  differences are no longer treated as errors. Both behaviours have regression coverage/documentation.
