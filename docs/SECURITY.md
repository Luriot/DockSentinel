# Security

DockSentinel is a self-hosted security tool that needs realistic descriptions of what it protects, what
it assumes, and where it is weak. This document is the working threat model and hardening guide.

## Assets and trust boundaries

| Asset | Why it matters |
| --- | --- |
| Docker endpoint credentials and TLS keys | Possession permits Docker API access, which is effectively host control |
| ntfy access token / credentials | Possession permits publishing into the operator's notification channel |
| DockSentinel administrator session | Full control over configured endpoints, notification targets and scan policy |
| Findings and scan history | Reveals weaknesses in the operator's infrastructure |
| Database volume (including `secret.key`) | Contains encrypted secrets, session hashes and the full history |

Trust boundaries:

- **Browser ↔ DockSentinel** — untrusted network in general; treated as hostile until authenticated.
- **DockSentinel ↔ Docker Engine** — the daemon is far more privileged than DockSentinel. Endpoint
  metadata (container names, labels, ports) is untrusted input and is treated as data.
- **DockSentinel ↔ scanner process** — Trivy is trusted code, but it processes hostile image content.
  It runs with a small environment, a timeout and output caps; results are validated before storage.
- **DockSentinel ↔ external feeds** — the CISA KEV JSON is untrusted data; only validated CVE IDs and
  bounded strings are stored.

Assumptions:

- The operator deploys DockSentinel on a trusted network or behind an authenticated TLS reverse proxy.
- The host, database volume and scanner binary are not already compromised. If an attacker can modify
  the database volume or replace the Trivy binary, they can influence results.
- Anyone with access to the Docker socket already has effective root-equivalent control. DockSentinel's
  read-only Docker usage reduces its own footprint; it does not reduce the risk of granting socket access.

## Authentication and sessions

- No default account and no unauthenticated administrative API. First-run setup requires a random
  setup token printed once in the logs (or supplied via `SETUP_TOKEN`), compared in constant time.
- One administrator account. Passwords are hashed with scrypt (`N=16384, r=8, p=1`, 64-byte key, random
  salt, parameters stored in the hash for future upgrades) and require at least 12 characters.
- Sessions: 32-byte random token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` when HTTPS or
  `COOKIE_SECURE=always`), stored hashed in SQLite with a 7-day sliding expiry, rotated on login and
  invalidated on password change/logout.
- CSRF: every mutating API request requires `X-CSRF-Token` matching the session; the frontend obtains it
  from `/api/auth/session`. Origin/Host are compared when an `Origin` header is present.
- Login and setup attempts are limited per IP (10 per 5 minutes). The limiter is in memory and resets on
  restart — documented, not hidden.
- Unauthenticated requests to unknown `/api/*` paths receive `401`, so route existence is not disclosed.
- Passwords are never returned or logged. Changing a password requires the current password and
  invalidates other sessions.

## Secret handling

- Docker TLS certificates/keys and ntfy credentials are encrypted at rest with AES-256-GCM using a
  32-byte key. The key comes from `DOCKSENTINEL_SECRET_KEY` or `DATA_DIR/secret.key` (created with mode
  `0600` where supported). Losing the key invalidates stored secrets only; it does not corrupt findings.
- API responses expose only whether a secret exists (`hasToken`, `hasTls`), never the secret value.
- Secrets are never passed to scanner child processes. The scanner environment is an allowlist: `PATH`,
  home/temp paths, locale, proxy variables and `TRIVY_CACHE_DIR`.
- pino redaction covers authorization headers, cookies, passwords, tokens and secrets in logs. Request
  logs contain method, URL, status and timing, not bodies or cookies.
- Client secrets are never written to the database in plaintext. Note that backups necessarily contain
  encrypted secrets and the key; protect backups accordingly.
- Opt-in secret scanning is deliberately metadata-only. Trivy writes a temporary JSON report containing raw
  matches/code into the per-scan scratch directory (mode `0700`, removed immediately after parsing). The
  parser never copies `Match`, `Code` or layer contents; SQLite, API responses, logs, notifications and UI
  contain only rule, category, path, line range and severity. Content-scan errors are generic and discard
  scanner stderr so secret material cannot leak through an error message.
- Secret findings can be false positives. A clean secret scan is not proof that an image contains no
  credentials.

## Native execution

- The native launcher stores the database, encryption key, scanner cache, scratch data and managed Trivy
  binary in a per-user data folder (`%LOCALAPPDATA%\DockSentinel`, Application Support, or XDG data),
  not in the repository. Set `DATA_DIR` deliberately if using a shared or service account.
- Native mode binds to `127.0.0.1` by default. Setting `HOST=0.0.0.0` exposes the same authenticated UI to
  the network and requires the same reverse-proxy/TLS care as the container deployment.
- The installer downloads only the pinned official Trivy release and (for the Windows installer) the
  official Node.js runtime. Both SHA-256 checksums are verified before extraction or execution; Trivy is
  installed atomically and checked with `trivy --version`. It never executes an unverified download. A
  user-supplied `TRIVY_BIN` is trusted as-is.
- Node.js 24.12+ remains a prerequisite; no self-contained executable is shipped. Node SEA is still active
  development and would add bundling/asset complexity without improving the supported Docker deployment.
- Windows Docker Desktop is reached through its named pipe (`//./pipe/docker_engine`), which has the same
  effective host-root privilege as the Unix socket. The same socket-access warnings apply.

## Docker socket access

Access to `/var/run/docker.sock` grants control of the Docker daemon and, through it, the host. Practical
consequences:

- A read-only bind mount does **not** make the API read-only. Permission derives from socket ownership,
  not mount flags.
- DockSentinel itself performs only `GET /_ping`, `GET /version`, `GET /containers/json`,
  `GET /images/json` and `GET /images/{id}/get`. It never starts, stops, restarts, deletes or inspects
  containers, and it does not read container environment variables.
- Running as non-root with `--group-add <socket GID>` is recommended. Running DockSentinel as root to
  access the socket widens the blast radius; if that is unavoidable, harden the host and network.
- A least-privilege socket proxy is a reasonable hardening step. DockSentinel needs the read-only
  endpoints above; a proxy such as `tecnativa/docker-socket-proxy` configured with `CONTAINERS=1`,
  `IMAGES=1` and `INFO=1` (and everything else disabled) covers them. Verify the proxy version's endpoint
  allowlist before relying on it, and treat the proxy itself as privileged infrastructure.
- Never publish the Docker TCP API without TLS **and** authentication. Plain `tcp://` endpoints are
  allowed only for a trusted private network and are visibly labelled as insecure in the UI.

## Remote TLS endpoints

- Preferred: mutual TLS (`tcp` with TLS, client certificate/key and CA). Certificates are validated by
  default. Skip-verification is available for self-signed endpoints and is clearly warned about.
- The malformed-address and PEM checks reject whitespace/newline injection attempts and non-PEM values
  before anything is stored.
- Trivy never receives the endpoint credentials because images are exported by DockSentinel itself.

## Process execution and scanner input

- No shell is used anywhere. Trivy is spawned with an argument array (`--input <archive>`,
  `--format json`, `--output <report>`, fixed profile flags). No endpoint name, image reference, label or
  user string is interpolated into a command.
- Image archives are requested by validated `sha256:<64 hex>` image IDs only.
- Hard limits: 15-minute scan timeout (configurable), 5-minute quick profile target, 10-minute export
  timeout, 96 MiB report limit, 8 GiB archive limit, 1 MiB stdout and 64 KiB stderr caps. Violations kill
  the process tree.
- Scanner output is parsed strictly. Malformed or truncated JSON fails the scan; it never becomes a clean
  result. Unknown severities become `UNKNOWN`, never a lower real severity.
- Trivy's vulnerability database is downloaded and verified by Trivy itself into a persistent cache. The
  database may be up to 24 hours stale between scheduled updates; scans record its timestamp and warn in
  the UI when the cached DB is older than seven days. If a database update fails, DockSentinel retries
  once with `--skip-db-update` and records a warning.

## HTTP and application security

- JSON-schema validation on bodies and query parameters; additional properties are stripped; request
  bodies are limited to 512 KiB.
- Parameterised SQL everywhere; no dynamic SQL derived from user input (the only interpolation is a
  backup path escaped by the backup script and an `IN (...)` placeholder list built from integers).
- Security headers: CSP (`default-src 'self'`, no inline scripts, `frame-ancestors 'none'`),
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, API `no-store`.
  HSTS is added when the request is HTTPS.
- The SPA fallback only serves `index.html` for non-API GET/HEAD requests; API 404s stay JSON.
- Container: minimal Debian slim base, pinned Trivy version, only `tini`/`gosu`/CA certificates added,
  one process, no added capabilities, `no-new-privileges` recommended in Compose, app process drops to
  the configured non-root UID/GID after preparing the data directory.
- Health and readiness: `/api/health` executes a database query and returns no secrets.

## Failure modes and truthfulness

- A failed, cancelled, timed-out or unparseable scan is never shown as clean. Previous findings remain
  attached to the last successful scan.
- "No findings" is always qualified by scan age and profile. The UI marks results older than the
  freshness window as stale and displays the last successful scan time.
- Exposure is represented as declared, potential, internal or unknown. Published ports are never
  presented as proof of Internet reachability.
- KEV data is explicitly tri-state (`yes`, `no`, `unknown`); when the feed has never synchronised,
  findings show `KEV unknown` rather than implying they are not exploited.
- The interface states that image scanning does not detect live compromise and is not an intrusion
  detection system.

## Known gaps and limitations

- No multi-factor authentication, SSO, or multiple users/roles. The model is a single trusted operator.
- No per-action audit trail beyond scans, finding events, alerts and structured request logs.
- Login/setup rate limiting is per-process and in memory; a restart clears counters.
- The setup token is printed to the process/container log. Protect log access and complete setup promptly.
- Docker API errors and vulnerability-scan stderr are stored/displayed; they can contain internal
  hostnames. Content-scan stderr is intentionally discarded. The UI is authenticated, but the database and
  backups then contain stored error text.
- KEV data is fetched over TLS from a single external source without signature verification beyond TLS.
  If the source is unavailable, last-known data is kept and marked stale.
- Trivy database freshness depends on outbound network access. An air-gapped deployment must pre-seed the
  cache (see [SCANNERS.md](SCANNERS.md)).
- A compromised Docker daemon or a malicious image can influence scanner output and resource usage.
  Timeouts, quotas and strict parsing reduce but do not eliminate that risk.
- No guarantee that every vulnerable dependency is detectable: scratch/distroless images, vendored code,
  statically linked libraries and packages without metadata may be missed. This is a scanner coverage
  limitation, not something DockSentinel asserts around.
- Deployment over plain HTTP exposes the session to network interception. Terminate TLS at the reverse
  proxy and set `TRUST_PROXY=true` and `COOKIE_SECURE=always`, or bind to a trusted interface.
- Native mode was executed on Windows only. The same Node code targets macOS/Linux, but the native
  installer/launcher path was not run there; treat those platforms as untested until verified.
- Content scanning is not a host, daemon, Kubernetes or running-container audit. It inspects image config
  and image files only, and image-content misconfiguration checks are useful only when IaC files are present.

## Hardening checklist

1. Put DockSentinel behind TLS (reverse proxy or private VPN); set `TRUST_PROXY=true` and
   `COOKIE_SECURE=always` when applicable.
2. Prefer Unix-socket access with a specific socket group, or mutual TLS for remote endpoints. Never
   expose an unauthenticated Docker TCP API.
3. Keep the data volume private to the container UID/GID; back it up encrypted.
4. Use a dedicated ntfy topic and access token; rotate it if exposed.
5. Keep the image pinned and updated; update the bundled Trivy version deliberately.
6. Set resource limits appropriate to the host (`MAX_IMAGE_EXPORT_BYTES`, memory/CPU limits) and monitor
   disk for the scratch directory.
7. Restrict who can reach the UI; there is no separate read-only role yet.
8. Review alerts and scan failures regularly; an unreachable endpoint must not be mistaken for a clean host.

## Reporting

This repository has no dedicated security contact or policy file. If you publish it, add a `SECURITY.md`
contact and a private disclosure channel before encouraging external reports.
