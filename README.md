# DockSentinel

DockSentinel is a lightweight, self-hosted **Docker vulnerability monitoring and alerting** service.
It discovers containers and images across one or more Docker endpoints, scans images with
[Trivy](https://trivy.dev/), keeps a history of findings, prioritises what is urgent, and sends
deduplicated notifications through [ntfy](https://ntfy.sh/).

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

- Multiple Docker environments (local Unix socket, Windows named pipe, TCP, or TLS with client
  certificates), each with independent health, inventory and scan policy.
- Container and image discovery with deduplication by immutable image ID. Findings map back to every
  container, environment and host that uses the image.
- Trivy integration with structured JSON output, quick and standard vulnerability profiles, scanner/DB
  version capture, update fallbacks, timeouts, output caps and safe process execution.
- Finding lifecycle: open, resolved, reappeared, severity changed. Failed scans never resolve findings
  and never masquerade as clean results.
- Prioritisation from severity, CISA KEV membership, fix availability, running state, network exposure
  metadata and Docker labels. Transparent, rule-based tiers — not a proprietary risk score.
- ntfy delivery with per-image grouping, deduplication keys, retries with backoff, a test action and a
  complete delivery history.
- Optional, opt-in Trivy **image configuration/content** checks for Dockerfile misconfigurations and
  embedded secrets. Secret matches are stored as metadata only; values are never persisted or displayed.
- SQLite persistence with versioned migrations, retention policies, health checks, graceful shutdown
  and backup/reset scripts.

## What it does not do

- No runtime intrusion detection, WAF, malware scanning or live-compromise detection.
- No guaranteed Internet exposure detection. Published Docker ports are evidence, not proof.
- No host, kernel or Docker-daemon audit. Misconfiguration and secret scans only inspect the **image**
  (image config and files inside the image), not the running container or host.
- No automatic remediation. DockSentinel never starts, stops, restarts or deletes containers.
- No SBOM management, VEX or license compliance platform.

## Install with Docker Compose

Requirements: Docker Engine with the Compose plugin, outbound HTTPS for Trivy and KEV updates, and a
writable data directory. The Trivy cache can grow to roughly 1–2 GiB after standard scans.

```bash
cp .env.example .env
# Optional: set SETUP_TOKEN in .env; otherwise a random token is printed once in the logs.
docker compose up -d --build
docker compose logs docksentinel | grep -i "setup token"
```

Open `http://<host>:8080`, enter the setup token, create the administrator account, then add a Docker
environment. Discovery and the first vulnerability scans are queued automatically.

A public multi-arch image is also published at `ghcr.io/luriot/docksentinel`:

```bash
docker pull ghcr.io/luriot/docksentinel:latest
```

The socket is mapped read-only, but Docker access is still **effectively host-root**. Read the
[Docker security notes](docs/SECURITY.md#docker-socket-access) before deploying on a host that matters.
If discovery fails with permission denied, set `DOCKER_GID` to the socket's group
(`stat -c '%g' /var/run/docker.sock`). Docker Desktop presents the Linux socket as `root:root` mode
`0660`, so container smoke tests need `PGID=0` or `--group-add 0`.

## Run natively (without the DockSentinel container)

DockSentinel itself can run directly with Node.js. This does **not** remove the need for a Docker
endpoint: use a local Docker Engine, a Windows Docker Desktop named pipe, or a remote TCP/TLS endpoint.

**Prerequisite:** Node.js **24.12 or newer** (the app uses native TypeScript execution and `node:sqlite`).
The installer downloads the matching official Trivy release and verifies its SHA-256 checksum.

```bash
npm ci
npm run native:setup          # builds the UI, installs verified Trivy into the native data folder
npm run native                # http://127.0.0.1:8080
# optional: npm run native -- --open
```

Native data defaults to a per-user application folder:

| Platform | Data folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\DockSentinel` |
| macOS | `~/Library/Application Support/DockSentinel` |
| Linux | `$XDG_DATA_HOME/docksentinel` or `~/.local/share/docksentinel` |

The database, encryption key, Trivy cache, scratch space and managed Trivy binary live there. Override
with `DATA_DIR`. The launcher binds to `127.0.0.1` by default; set `HOST`/`PORT` deliberately to expose it.

Add a Docker environment after setup:

- **Windows Docker Desktop:** kind `unix`, address `//./pipe/docker_engine`.
- **Linux/macOS local Docker:** kind `unix`, address `/var/run/docker.sock`.
- **Remote:** kind `tcp` or `tls`, address `host:2376`.

If the app starts without a scanner, it reports that clearly and scans fail rather than appearing clean.
Re-run `npm run native:setup -- --force` to repair or update the managed Trivy copy. A self-contained
single executable is not provided: Node's SEA feature is still active development, and the Docker image
already provides a dependency-free deployment. On unsupported platforms, install Trivy manually and set
`TRIVY_BIN`.

## First-run and operations

- The setup token is printed once in the logs (or supplied with `SETUP_TOKEN`).
- Native mode: `DATA_DIR` persists settings, credentials, history and the scanner cache across restarts.
- Docker mode: persist `/data` as a volume; back up the database and `secret.key` together.
- Graceful shutdown handles `SIGINT`/`SIGTERM`; interrupted scans are recovered on the next start.
- Port conflicts, a missing UI build, an unwritable data folder and missing dependencies produce
  actionable startup errors.

## Content and configuration scans (opt-in)

Enable **misconfiguration scans** and/or **secret scans** in Settings, then use **Content scan** in an
image's drawer. These are separate from vulnerability scans and do not feed vulnerability counts, alerts
or image scan status.

- Misconfigurations use Trivy's Dockerfile-converted image config and any IaC files inside the image.
  This is not a host or daemon audit.
- Secret scans inspect image files and image config. DockSentinel stores only rule, location, category
  and severity; the matched value is never stored, returned, logged or notified. False positives are
  possible, and a clean secret scan is not proof that an image contains no credentials.
- Content findings have their own lifecycle and page. Failed content scans never resolve prior findings.

## Development

```bash
npm install
npm run dev            # backend on :8080
npm run dev:web        # Vite on :5173 with /api proxy
```

Press **Ctrl + Shift + B** in VS Code to start both as background tasks (`.vscode/tasks.json`). The
compound task stops both processes together.

```bash
npm run typecheck
npm test               # unit + integration; real Trivy tests skip if unavailable
npx playwright install chromium
npm run test:ui
npm run build
npm start              # production UI + API on :8080
```

## Configuration

Environment variables are documented in [`.env.example`](.env.example). Operational policy is managed in
the UI and stored in SQLite.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATA_DIR` | `./data` (`npm start`); per-user folder (native launcher) | Database, secret key, cache, scratch |
| `HOST` / `PORT` | `0.0.0.0` / `8080` (`127.0.0.1` for native launcher) | HTTP listener |
| `LOG_LEVEL` | `info` | Structured JSON logs |
| `TRUST_PROXY` | `false` | Honour `X-Forwarded-*` from a trusted proxy |
| `COOKIE_SECURE` | `auto` | `always` / `never` / `auto` |
| `SETUP_TOKEN` | random, logged once | First-run administrator token |
| `DOCKSENTINEL_SECRET_KEY` | `DATA_DIR/secret.key` | 32-byte encryption key |
| `TRIVY_BIN` / `TRIVY_CACHE_DIR` | `trivy` / `DATA_DIR/trivy-cache` | Scanner and cache |
| `SCAN_TIMEOUT_MS` | `900000` | Hard scan timeout |
| `SCAN_MAX_OUTPUT_BYTES` | `96 MiB` | Maximum report size |
| `MAX_IMAGE_EXPORT_BYTES` | `8 GiB` | Maximum image archive size |
| `SCAN_CONCURRENCY` | `2` | Concurrent scan ceiling |

Container permissions: `PUID`/`PGID` control the runtime user; `DOCKER_GID` grants socket access.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — modules, data model, scan flow, prioritisation, trade-offs.
- [Security](docs/SECURITY.md) — threat model, controls, Docker access, known gaps, hardening.
- [Scanner coverage](docs/SCANNERS.md) — vulnerability, misconfiguration and secret coverage, limits.
- [Deployment](docs/DEPLOYMENT.md) — Docker, native mode, TLS, upgrades, backup/restore, troubleshooting.
- [Unraid](docs/UNRAID.md) — template, socket permissions, updates.
- [HTTP API](docs/API.md) — authentication and endpoints.
- [Implementation handoff](HANDOFF.md) — maintainer notes, executed verification and remaining actions.

## License

MIT. See [LICENSE](LICENSE).
