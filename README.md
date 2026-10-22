# DockSentinel

DockSentinel is a lightweight, self-hosted **Docker vulnerability monitoring and alerting** service.
It discovers containers and images across one or more Docker endpoints, scans images with
[Trivy](https://trivy.dev/), keeps a history of findings, prioritises what is actually urgent, and
sends deduplicated notifications through [ntfy](https://ntfy.sh/).

It is an orchestration and correlation layer. It does **not** implement a vulnerability scanner,
vulnerability database, package parser or runtime intrusion detection.

```
Docker endpoints ──► discovery ──► image scan (Trivy) ──► normalised findings ──► lifecycle + history
                                                              │
                                                     priority / exposure / KEV
                                                              │
                                                           ntfy alerts
```

## What it does

- Multiple Docker environments (local Unix socket, TCP, or TLS with client certificates), each with
  independent connection health, inventory and scan policy. One unreachable host never blocks the
  others.
- Container and image discovery with deduplication by immutable image ID. Findings map back to every
  container, environment and host that uses the image.
- Trivy integration with structured JSON output, two genuinely different profiles, scanner/DB version
  capture, update fallbacks, timeouts, output caps and safe process execution.
- Finding lifecycle: open, resolved, reappeared, severity changed. Failed scans never resolve findings
  and never masquerade as clean results.
- Prioritisation from severity, CISA KEV membership (optional feed), fix availability, running state,
  network exposure metadata and Docker labels. Transparent, rule-based tiers — not a proprietary risk
  score.
- ntfy delivery with per-image grouping, deduplication keys, retries with backoff, a test action and a
  complete delivery history.
- Dashboard for the urgent-vulnerability workflow: overview, environments, containers, images,
  vulnerabilities, scan activity, notifications and settings.
- SQLite persistence with versioned migrations, retention policies, health checks, graceful shutdown
  and backup/reset scripts.

## What it does not do

- No runtime intrusion detection, WAF, malware scanning or live-compromise detection.
- No guaranteed Internet exposure detection. Published Docker ports are evidence, not proof: firewalls,
  reverse proxies, NAT and cloud security groups sit in between. Exposure is reported as *confirmed by
  an explicit label*, *potentially exposed from Docker metadata*, *no published ports* or *unknown*.
- No misconfiguration, secret or license scanning in this release. Image vulnerability scanning only.
- No container remediation. DockSentinel never starts, stops, restarts or deletes containers.
- No host vulnerability scanning, kernel scanning or SBOM management.

## Quick start (Docker Compose)

Requirements: Docker Engine with the Compose plugin, outbound HTTPS for Trivy database and KEV
updates, and a writable appdata directory. Expect roughly 1–2 GiB of Trivy cache after standard scans
(the Java index is large); budget disk accordingly.

```bash
cp .env.example .env
# Optional: set SETUP_TOKEN in .env, otherwise a random token is printed in the logs.
docker compose up -d --build
docker compose logs docksentinel | grep -i "setup token"
```

Open `http://<host>:8080`, enter the setup token, create the administrator account, then add a Docker
environment (start with the local socket `/var/run/docker.sock`). Discovery and the first scans are
queued automatically.

The Compose file builds locally by default. Published images are available at
`ghcr.io/luriot/docksentinel` (`latest`, `main`, `sha-<commit>`). The package is currently private:
to pull it, `docker login ghcr.io` with a token that has `read:packages`, or change the package
visibility to public. A locally built image needs no registry login.

The socket is mapped read-only, but Docker access is still **effectively host-root**. Read the
[Docker security notes](docs/SECURITY.md#docker-socket-access) before deploying on a host that matters.
If discovery fails with permission denied, add the socket's group ID (`stat -c '%g' /var/run/docker.sock`)
to `DOCKER_GID` before starting. Docker Desktop (Windows/macOS) presents the Linux socket as
`root:root` mode `0660`, so local testing needs `DOCKER_GID=0` or `--group-add 0`.

See [Deployment](docs/DEPLOYMENT.md) for reverse proxies, remote TLS endpoints, upgrades, backups and
troubleshooting, and [Unraid](docs/UNRAID.md) for the Unraid template.

## Local development

Node.js **>= 24.12** is required. Node 24 runs the TypeScript backend directly (type stripping) and
provides the built-in SQLite driver; there is no ORM and no separate backend build step. A local
`trivy` binary is needed only to exercise real scans.

```bash
npm install
npm run dev            # API on http://127.0.0.1:8080 with DATA_DIR=./data
npm run dev:web        # Vite dev server on http://127.0.0.1:5173 (proxies /api)
```

Build and run like production:

```bash
npm run build          # typecheck + production SPA build
npm start
```

Tests:

```bash
npm test               # unit + integration (uses real Trivy when available and cached DB present)
npm run typecheck
npx playwright install chromium
npm run test:ui        # starts seeded instances and drives Chromium
```

Integration tests that need a real scanner skip themselves when Trivy or its vulnerability database is
not available on the machine. A plain Docker daemon is **not** required by the test suite: discovery
and export are exercised against a spec-shaped fake Docker API, and Trivy scans a deterministic synthetic
image archive.

## Configuration

All configuration is environment variables (see [`.env.example`](.env.example)); operational policy
(intervals, thresholds, notification settings, retention) is configured in the UI and stored in SQLite.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATA_DIR` | `./data` | Database, secret key, Trivy cache, scan scratch space |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | HTTP listener |
| `LOG_LEVEL` | `info` | Structured JSON logs |
| `TRUST_PROXY` | `false` | Honour `X-Forwarded-*` from a trusted reverse proxy |
| `COOKIE_SECURE` | `auto` | `always` / `never` / `auto` for the session cookie |
| `SETUP_TOKEN` | random, logged once | First-run administrator setup token |
| `DOCKSENTINEL_SECRET_KEY` | `DATA_DIR/secret.key` | 32-byte key for encrypted TLS material and notification credentials |
| `TRIVY_BIN` / `TRIVY_CACHE_DIR` | `trivy` / `DATA_DIR/trivy-cache` | Scanner binary and database cache |
| `SCAN_TIMEOUT_MS` | `900000` (15 min) | Hard scan timeout |
| `SCAN_MAX_OUTPUT_BYTES` | `96 MiB` | Maximum scanner report size |
| `MAX_IMAGE_EXPORT_BYTES` | `8 GiB` | Maximum image archive streamed from Docker |
| `IMAGE_EXPORT_TIMEOUT_MS` | `600000` (10 min) | Image export timeout |
| `SCAN_CONCURRENCY` | `2` | Upper bound on concurrent scans |
| `KEV_URL` | CISA feed | Known-exploited catalogue source |

Container permissions: `PUID`/`PGID` control the runtime user (default `10001`), and `DOCKER_GID`
(or `--group-add` on Unraid) grants access to the Docker socket.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — modules, data model, scan flow, prioritisation, trade-offs.
- [Security](docs/SECURITY.md) — threat model, controls, Docker access, known gaps, hardening.
- [Scanner coverage](docs/SCANNERS.md) — what Trivy detects here, profiles, failure semantics, offline use.
- [Deployment](docs/DEPLOYMENT.md) — Compose, TLS, upgrades, backup/restore, troubleshooting.
- [Unraid](docs/UNRAID.md) — template, socket permissions, updates.
- [HTTP API](docs/API.md) — authentication and endpoints.
- [Handoff notes](HANDOFF.md) — implementation status, executed test results and remaining actions.

## Verification status

Last verified on 2026-10-22 with Node.js 26.4.0 (Windows), Docker Desktop 4.96.2 / Engine 29.9.2,
Trivy 0.75.0 and Chromium 156:

- `npm test` — **63 tests passing** (unit + integration), including a rescan-stability regression test.
- Real Trivy end-to-end test — synthetic Debian 11 image produced **61 findings** (3 critical, 10 high,
  26 medium, 20 low, 2 unknown); normalisation, priority tiers, failure preservation and cleanup asserted.
- `npm run typecheck` — backend and web typechecks pass.
- Production SPA build — JS ≈ 355 kB (≈ 98 kB gzip), CSS ≈ 25 kB (≈ 6 kB gzip).
- `npm run test:ui` — **11 Playwright tests passing** (setup, login, overview, filters, drawers,
  environment validation, scan failure states, notification validation, settings persistence,
  mobile layout, keyboard basics).
- **Production image** — built with `docker buildx build --platform linux/amd64 --load`, Dockerfile
  check reported no warnings, container starts healthy and runs the app as non-root UID 10001.
- **Real Docker Desktop validation** — discovered the running containers, scanned
  `nginx:1.19-alpine` (**96 findings: 9 critical, 52 high, 29 medium, 6 low; all fixable**) in 14.4 s
  on first scan and 0.19 s with a warm cache, delivered the grouped ntfy alert, and verified stable
  re-scanning (no resolved/recreated findings), restart persistence, graceful shutdown and interrupted
  scan requeue. Screenshots: `test-results/screens/real-overview.png`.
- **Published image** — `ghcr.io/luriot/docksentinel` (`latest`, `main`, `sha-a45adfe`), manifest
  `sha256:8922728e…`, built for **linux/amd64 + linux/arm64** and verified in the workflow. BuildKit
  attached SBOM and provenance attestations; the public GitHub artifact attestation was signed with
  Sigstore and uploaded to Rekor. The GHCR package itself is still **private** (independent of the now
  public repository), so pulling it anonymously is denied until its visibility is changed or credentials
  are supplied.
- **Not yet verified:** Unraid or any remote Docker host, mutual-TLS endpoints, and running the arm64
  image on real arm64 hardware.

## License

MIT. See [LICENSE](LICENSE).
