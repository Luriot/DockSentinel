# Architecture

DockSentinel is a modular monolith: one Node.js process serving the API and the built single-page UI,
with an embedded SQLite database and a child-process integration to Trivy. This document describes the
modules, the data model, the scan lifecycle and the trade-offs behind the design.

## Technology choices

| Concern | Choice | Why |
| --- | --- | --- |
| Runtime | Node.js 24 LTS | Already required by the web toolchain; native TypeScript execution and built-in SQLite remove a build step and native modules |
| HTTP | Fastify 5 | Schema validation, hooks, static serving, structured logging, mature maintenance |
| Database | SQLite via `node:sqlite` | Single-instance workload with modest write volume; zero external infrastructure; WAL for concurrent readers |
| UI | React 19 + Vite + hand-written CSS | Dense technical UI without a component-library dependency; small bundle, no runtime CSS-in-JS |
| Docker API | `node:http`/`node:https` client over Unix socket or TCP/TLS | Only four GET endpoints are needed; avoids a Docker SDK dependency and requires no CLI |
| Scanner | Trivy child process | Purpose-built, actively maintained scanner with structured JSON output; DockSentinel only orchestrates it |
| Tests | `node:test` + Playwright | No test framework dependency for the backend; real browser coverage for the main journeys |

Deliberate omissions: no ORM (SQL is small and explicit), no cron library (one interval loop), no Docker
SDK, no shell execution anywhere, no message queue, no separate worker service.

## Module map

```
src/
├─ index.ts                 process bootstrap, background workers, graceful shutdown
├─ config.ts                environment parsing, secret-key loading
├─ logger.ts                pino logger with redaction paths
├─ db/
│  ├─ migrations.ts         append-only versioned schema
│  └─ index.ts              connection, PRAGMAs, migrations, transactions
├─ domain/                  pure rules and reusable types
│  ├─ severity.ts           severity normalisation and ordering
│  ├─ exposure.ts           Docker-metadata exposure classification
│  ├─ priority.ts           transparent priority tiers
│  ├─ policy.ts             labels and alert thresholds
│  ├─ labels.ts             label allowlist
│  ├─ findings.ts           normalised finding type, diffing, counting
│  └─ content.ts            opt-in misconfiguration/secret metadata and identity
├─ docker/
│  ├─ client.ts             read-only Docker API client (unix/tcp/tls), image export
│  ├─ detect.ts             local Docker candidate probing for first-run setup
│  └─ normalize.ts          Docker JSON → internal container/image shapes
├─ discovery.ts             per-endpoint discovery and connectivity test
├─ scanner/
│  ├─ process.ts            safe child-process runner (no shell, timeout, caps, kill tree)
│  ├─ trivy.ts              Trivy adapter: profiles, env allowlist, retries, version
│  ├─ normalize.ts          strict Trivy JSON parsing and normalisation
│  ├─ validate.ts           URL/CVSS validation helpers
│  └─ info.ts               cached scanner availability probe
├─ scan/
│  ├─ coordinator.ts        queue workers, export + scan, apply results, retries
│  └─ recovery.ts           interrupted-scan requeue/fail policy
├─ jobs/
│  ├─ scheduler.ts          discovery cadence, due scans, stale alerts, KEV sync, maintenance
│  └─ maintenance.ts        retention pruning, checkpoints, session cleanup
├─ intel/kev-service.ts     CISA KEV sync with overlap guard and alert hand-off
├─ notify/
│  ├─ ntfy.ts               ntfy HTTP publish client and validation
│  ├─ messages.ts           Markdown message templates
│  ├─ service.ts            alert evaluation, thresholds, deduplication
│  └─ dispatcher.ts         delivery loop, retries/backoff, history
├─ repo/                    SQL access grouped by aggregate
│  ├─ environments, images, containers, findings, content, scans, alerts, settings, kev, overview
├─ startup.ts               startup preflight and actionable errors
├─ backup.ts                VACUUM INTO backup, staging and startup restore
├─ system/update.ts         GitHub release update check
├─ auth.ts, passwords.ts, secrets.ts, security/rate-limit.ts
├─ scripts/native.ts        native launcher (loopback default, managed Trivy)
├─ scripts/native-setup.ts  UI build + checksum-verified Trivy installer
├─ scripts/install-windows.ps1  double-click Windows installer (portable Node + shortcuts)
├─ web/src/views/Welcome.tsx    one-click first-run Docker onboarding
├─ api/
│  ├─ server.ts             Fastify instance, security headers, auth hook, static SPA
│  ├─ http.ts               session/CSRF/origin helpers, pagination
│  └─ routes/               auth, environments, inventory, findings, content, scans, system
└─ web/                     React SPA source (built to web/dist)
```

Dependencies flow downward: `api` → services → `repo` → `db`; `domain` is pure and dependency-free.
Scanner-specific behaviour stays inside `scanner/trivy.ts`; Docker-specific behaviour inside `docker/`.

## Data model

SQLite is opened in WAL mode with foreign keys enabled, `synchronous=NORMAL`, a 5 s busy timeout and
16 MiB cache. All tables are `STRICT`. All writes are synchronous on the single event loop, so
transactions cannot interleave with other writers.

| Table | Purpose |
| --- | --- |
| `users`, `sessions` | Single administrator; scrypt password hash; hashed session tokens with CSRF token and expiry |
| `settings` | One JSON document with validated application policy; secrets stored encrypted inside it |
| `environments` | Docker endpoints: kind (`unix`/`tcp`/`tls`), address, encrypted TLS material, status, scan policy |
| `images` | Keyed by immutable Docker image ID (`sha256:…`), plus OS, size, last scan status and denormalised finding counts |
| `image_locations` | Which tag/digest reference exists on which environment (replaced atomically on discovery) |
| `containers` | Current inventory keyed by `(environment_id, docker_id)`, state, filtered labels, ports, exposure classification, `present` flag |
| `scans` | One row per attempt: kind (`vulnerability`/`content`), profile, trigger, status, timings, counts, scanner/DB versions, error, warnings, attempt count |
| `findings` | Current vulnerability state per image/identity, severity, fix, CVSS, KEV flag, episode, first/last seen, resolution, triage status/note |
| `content_findings` | Opt-in misconfiguration/secret metadata per image/identity; rule, path, line, category, severity, episode, resolution. Never secret values or code |
| `finding_events` | Append-only lifecycle history: appeared, resolved, reappeared, changed |
| `alerts` | Notification records with dedupe key, rendered body, delivery status, attempts, last error, next attempt |
| `kev`, `kev_sync` | CISA catalogue snapshot and last synchronization outcome |

Finding identity is `(image_id, target, vuln_id, pkg_name, installed_version)`. `episode` increments
when a resolved finding reappears, which keeps alert dedupe keys meaningful across episodes.

Image identity is the Docker image ID reported by the API (`/images/json`), not a tag. Tags move; image
IDs do not. On containerd-backed engines this ID is the manifest digest, while Trivy reports the config
digest from the exported archive; DockSentinel attributes findings to the ID it requested from Docker and
does not treat that difference as an error. Repository digests are stored for display; the archive is
always requested by the immutable image ID.

## Discovery flow

1. Scheduler considers each enabled environment due when `last_discovery_at` is older than the
   configured interval (default 10 minutes).
2. A read-only Docker client calls `/_ping`, `/version`, `/containers/json?all=1` and `/images/json`.
   Scripts, environment variables, container filesystems and full inspect payloads are never read.
3. Only `docksentinel.*` labels are retained from container metadata. Ports, state, network mode and
   timestamps are normalised. Exposure is classified from published host IPs and labels.
4. In one transaction: images are upserted, image locations are replaced for that environment, and
   containers are upserted while missing containers are marked `present = 0`. Container and image rows
   on other environments are untouched.
5. Endpoint status, last contact and last discovery are recorded. A failure marks only that endpoint
   offline and records the error; other environments continue.

Containers are never removed automatically; they are marked absent and pruned by retention after 30 days.

## Scan flow

```
scheduler / manual action
        │  queueScan() (idle check, priority, trigger)
        ▼
  coordinator.tick() ── claimNextScan()  (one scan per environment, global limit)
        ▼
  mkdtemp under DATA_DIR/tmp
        ▼
  Docker GET /images/{imageID}/get  →  image.tar (size-capped, timeout, abortable)
        ▼
  trivy image --input image.tar --format json --output report.json \
        --scanners vuln --vuln-type <profile> --cache-dir <volume> [--skip-java-db-update]
        ▼
  strict JSON parse → NormalizedFinding[]
        ▼
  transaction: diff findings, write events, resolve disappeared findings,
               update image counters, mark scan success
        ▼
  alert evaluation (new/resolved/fixes/KEV) → alerts queue → dispatcher → ntfy
```

A content scan follows the same queue/export/scratch path but branches at the scanner arguments
(`--scanners misconfig,secret --image-config-scanners misconfig,secret`). Its findings are written to
`content_findings`, never to vulnerability counters or alert evaluation, and only a successful, parsed
report may resolve previous content findings. The raw secret `Match`/code fields are dropped during
parsing.

## Triage, status and backups

Triage is stored on the finding row (`triage_status`, `triage_note`, `triaged_at`). Acknowledged findings
remain visible; ignored and false-positive findings are excluded from default lists, overview/image counts,
and alerts until cleared. `refreshImageFindingCounts()` keeps denormalised image counters consistent.

The System Status page reads `GET /api/system/status` (Docker host states, scanner/KEV, `statfs` disk usage,
backup files, app version). Backups are filesystem snapshots under `DATA_DIR/backups`, not database tables. Backups use `VACUUM INTO`; restore stages a validated SQLite file and applies it
before the database opens on the next start, retaining a pre-restore copy. Update checks use the fixed
GitHub releases API, not a user-supplied URL.

## Native bootstrap

`scripts/native.ts` sets a per-user `DATA_DIR`, binds to `127.0.0.1` unless configured otherwise, selects
the managed or configured Trivy binary, and calls the exported `start()` bootstrap. `native-setup.ts`
builds the SPA and downloads the pinned official Trivy archive, verifies its SHA-256 checksum, installs it
atomically and checks `trivy --version`. `install-windows.ps1` additionally installs a checksum-verified
private Node.js runtime and creates per-user shortcuts, so Windows users do not need system Node/Trivy.
Startup preflight reports a missing UI build, unwritable data folder, port conflict and unsupported Node
version with actionable messages. `GET /api/environments/detect` probes local Docker Desktop named pipes
and Unix sockets; the welcome screen uses `POST /api/environments/local` to create the host and run
discovery in one click. The Docker entrypoint is unchanged.

Why export the image instead of letting Trivy talk to the Docker daemon:

- The scanner receives **no Docker credentials**. DockSentinel's own read-only client performs the
  export, including TLS with optional certificate verification.
- Scanning is bound to the **immutable image ID**, so a tag moving between discovery and scan cannot
  attribute findings to the wrong image.
- The same code path works for local sockets, remote TCP and mutual TLS.
- The cost is temporary disk I/O equal to the image archive, bounded by `MAX_IMAGE_EXPORT_BYTES`
  (default 8 GiB) and removed in a `finally` block. Trivy itself also unpacks layers to scan them.

Failures mark the scan failed and preserve previous findings. Only a successfully parsed report can
resolve findings or produce a clean result. Unparseable output, timeouts and non-zero exits are failures.

### Scheduling, concurrency and retries

- Two profiles:
  - **quick** — OS packages only, skips the Java index, 5-minute target timeout. Cheap recurring scan.
  - **standard** — OS and language packages, 15-minute target timeout. Deeper scan; may download the Java
    index on first use.
- Per-environment intervals are configurable (`quick_interval_hours`, `standard_interval_hours`); the
  scheduler uses the minimum enabled interval among environments that hold the image. Standard wins when
  both are due.
- Images must be used by at least one present container to be scheduled. Newly discovered, never-scanned
  images are queued automatically when `scanOnDiscovery` is enabled.
- A scan is never queued if another scan for the same image is queued or running.
- Concurrency is `min(UI setting, SCAN_CONCURRENCY env)`; only one scan per environment runs at a time.
- Transient failures (Docker unreachable, export failure, timeout, scanner failure, DB unavailable) are
  retried with exponential backoff while the configured retry budget lasts. Final failure creates one
  alert per image/environment/day.
- On startup, scans left `running` are requeued if attempts remain, otherwise marked failed with
  `interrupted`. Scratch directories are deleted.
- Service shutdown aborts in-flight scans, marks them interrupted, and requeues them for the next start.

Freshness is about vulnerability intelligence, not just image bytes: every image is rescanned on its
schedule even when the digest is unchanged, because new CVEs are disclosed against unchanged packages.

## Prioritisation and exposure

Priority is a transparent, rule-based ranking used for ordering and tier badges. It is **not** a risk
score and does not claim to predict exploitation.

| Signal | Weight |
| --- | --- |
| Severity base | CRITICAL 50 · HIGH 30 · MEDIUM 10 · LOW 2 · UNKNOWN 0 |
| CISA KEV member | +40 |
| Fixed version listed | +10 |
| Used by a running container | +8 |
| Exposure: declared Internet-facing | +15 |
| Exposure: potentially exposed (published port / host network) | +6 |
| Workload label `criticality=critical` | +10 |
| Workload label `criticality=high` | +5 |
| Workload label `criticality=low` | −5 |

Tiers: score ≥ 70 → P1, ≥ 50 → P2, ≥ 30 → P3, otherwise P4. Findings are always ordered by severity
first, then score, so contextual bonuses cannot push a HIGH above a CRITICAL.

Exposure states:

- **confirmed / Internet exposure declared** — the user asserted it with `docksentinel.exposure=internet`.
- **potential** — a published port bound to `0.0.0.0`/`::`, a published port on a specific non-loopback
  interface, or host networking. This is a clue, never proof of public reachability.
- **internal** — no published ports, or only loopback-published ports.
- **unknown** — container not running, or insufficient metadata.

Supported container labels (other labels are deliberately discarded):

| Label | Effect |
| --- | --- |
| `docksentinel.exposure` | `internet` / `public` / `internal` / `private` / `none` |
| `docksentinel.monitor` | `false` excludes the container from alert evaluation |
| `docksentinel.criticality` | `critical` / `high` / `normal` / `low` |
| `docksentinel.alert-min-severity` | Overrides the global/environment threshold for this workload |
| `docksentinel.ignore-vulns` | Comma-separated vulnerability IDs to suppress for this workload |

## Alerting pipeline

Alert evaluation runs after a successful scan (or a final scan failure, KEV change, or stale check):

1. Affected monitored containers are resolved.
2. The threshold is the stricter of global and environment minimum severity, unless a container label
   overrides it. Findings ignored by every container are dropped.
3. One alert row is produced per image per scan for new findings, one for resolved findings, one for
   newly available fixes; KEV changes are grouped per image; failures are per image/environment/day;
   stale results per image/day.
4. Dedupe keys make insertion idempotent (`new:<image>:<scan>`, `resolved:<image>:<scan>`,
   `fix:<image>:<scan>`, `kev:<image>:<finding-set hash>`, `scan_failed:<env>:<image>:<day>`,
   `stale:<image>:<day>`, `test:<timestamp>`).
5. The dispatcher claims alerts, sends them through ntfy, and records attempts. Failures are retried
   after 1, 5, 15 and 60 minutes; after five attempts the alert is marked failed. A crash in the middle
   of a delivery resets `sending` alerts to pending on the next start.
6. Messages are Markdown with the image, affected containers and exposure, severity counts, top findings,
   fix availability, links to advisories, verification time and a dashboard link when `publicUrl` is set.

The same scan cannot produce duplicate alerts; a quiet scan produces none. Resolved alerts are only
emitted after a successful scan omits the finding.

## Retention and recovery

A daily maintenance task prunes scan history (keeping the most recent scan per image), delivered alert
history, finding events, resolved findings for images no longer used by containers, removed containers,
orphaned images and expired sessions. It then runs `PRAGMA optimize` and a WAL checkpoint. The database
is never silently rebuilt.

Backups use SQLite `VACUUM INTO` (`scripts/backup.ts`), which produces a consistent snapshot while the
service runs. The encryption key must be backed up with the database to restore TLS material and
notification credentials.

## Prior art reviewed

`jwang996/runtime-vulnerability-scan` (runtime-vul-detect) is a small, actively maintained scanner that
inspired several decisions here. It discovers images in use, scans them on a cron schedule with Trivy,
deduplicates by image digest, and emits structured JSON logs for Loki/SIEM ingestion. Its deployment uses a
GET-only Docker socket proxy with an endpoint allowlist, a read-only root filesystem and dropped
capabilities, and it pins the Trivy version and caches the database.

Adopted where they fit:

- Scan only images referenced by containers, and correlate by immutable image ID.
- Keep the Docker API access read-only and GET-only; document the socket-proxy option.
- Persist Trivy's cache and record its version/timestamp; rescans are scheduled because vulnerability
  intelligence changes independently of image digests.
- Structured JSON logs and a pinned scanner version.

Where DockSentinel deliberately goes further: it persists findings and their lifecycle, deduplicates
alerts, prioritises by KEV/fix/exposure and keeps scan history, instead of emitting log lines only. Its
"runtime" name refers to scanning images that are already deployed, not to runtime intrusion detection;
DockSentinel uses the same honest framing. A Trivy server mode (one long-lived process sharing the loaded
database) would amortise per-scan database loading for hosts with hundreds of unique images; it is a
sensible future optimisation, not part of this MVP.

## Deliberate trade-offs and limits

- **Single instance only.** SQLite, in-process scheduling and the in-memory login limiter assume one
  process. Horizontal scaling is explicitly out of scope.
- **Image export needs scratch disk.** Scanning a large image temporarily writes an archive under
  `DATA_DIR/tmp`. This is capped and cleaned, but it is real disk usage.
- **No full Docker inspect.** Container environment variables, mounts and full configuration are never
  read; only list metadata. Exposure inference is therefore limited to ports, state, network mode and
  labels.
- **Unversioned Docker API paths.** Requests omit `/v1.x`, which Docker resolves to a supported version.
- **KEV feed is enrichment only.** The CISA JSON feed is fetched daily; a failure keeps the previous
  snapshot and marks it stale. KEV membership does not prove a particular deployment is exploitable.
- **Scanner profiles are code-defined.** UI users cannot inject arbitrary Trivy flags; changing options
  requires a code change, which keeps the process invocation auditable.
- **Rate limiting is in-memory.** Restarting clears login attempt counters. This is documented, not
  hidden.
- **No audit log of UI configuration changes.** Scan history, finding events and alert history are
  recorded; administrative CRUD is visible in structured logs but not a dedicated audit trail.

## Extensibility

The scanner boundary is a small interface (`ScannerAdapter.run()` returning normalised findings plus
scanner metadata). A second scanner should live in its own adapter, keep its CLI/API details local, and
normalise into `NormalizedFinding`; the persistence, lifecycle and alerting layers do not change.
Additional notification providers belong behind the same dispatch loop with an adapter that maps the
rendered message to the provider's payload.

Runtime security integrations are deliberately out of scope for the MVP; adding one would be a different
product, not a scanner adapter.
