# Deployment

This guide covers running DockSentinel with Docker Compose, connecting Docker endpoints securely,
reverse-proxying it, upgrading, backing up and troubleshooting.

## Requirements

- Docker Engine 20.10+ and the Compose plugin.
- A writable data directory for the database, encryption key, Trivy cache and scan scratch space.
- Outbound HTTPS to `ghcr.io/aquasec/trivy-db` (Trivy database) and `www.cisa.gov` (optional KEV feed).
- Disk headroom: the Trivy cache grows to roughly 1–2 GiB after standard scans (the Java index is
  large), plus temporary image archives up to `MAX_IMAGE_EXPORT_BYTES` (default 8 GiB) per concurrent scan.
- CPU/RAM: 1–2 vCPU and 1–2 GiB are enough for a small home lab; memory rises while Trivy unpacks large
  images. Two concurrent scans are the default.

## Native mode (no DockSentinel container)

DockSentinel can run directly with Node.js while still monitoring Docker endpoints. The app process does
not require Docker, but a Docker endpoint is still needed to discover and scan workloads.

### Windows installer

Double-click `Install-DockSentinel.cmd` from the DockSentinel folder. It installs a private Node.js
24.12 runtime and verified Trivy under `%LOCALAPPDATA%\DockSentinel`, runs the UI build, creates Desktop
and Start Menu shortcuts, and launches DockSentinel. It does not require administrator rights or a system
Node.js/Trivy installation. Node and Trivy downloads are checksum-verified before execution.

### Command-line (macOS/Linux/advanced)

**Prerequisite:** Node.js 24.12+ (native TypeScript execution and `node:sqlite`). Node's single-executable
application support is still active development and would require bundling/asset plumbing, so this release
does not ship a self-contained executable. The Docker image remains the dependency-free deployment.

```bash
npm ci
npm run native:setup
npm run native
# optional: npm run native -- --open
```

`native:setup` builds the production UI and downloads the pinned Trivy release matching the OS/architecture
from the official GitHub release. It verifies the SHA-256 checksum before extracting or executing the binary,
installs it atomically, and verifies `trivy --version`. Use `--force` to reinstall. `TRIVY_VERSION` overrides
the pinned version (checksums still required). `TRIVY_BIN` selects an existing scanner at launch; the
setup command still installs the managed copy.

Native data is per-user and persistent:

| Platform | Default |
| --- | --- |
| Windows | `%LOCALAPPDATA%\DockSentinel` |
| macOS | `~/Library/Application Support/DockSentinel` |
| Linux | `$XDG_DATA_HOME/docksentinel` or `~/.local/share/docksentinel` |

It contains the SQLite database, `secret.key`, `tools/trivy[.exe]`, `trivy-cache` and `tmp`. Override with
`DATA_DIR`. The launcher binds to `127.0.0.1` by default; set `HOST` deliberately to expose it. Startup
failures (port in use, missing UI build, unwritable data folder, missing scanner) print actionable messages.

Connect Docker after setup:

- Windows Docker Desktop: kind `unix`, address `//./pipe/dockerDesktopLinuxEngine` (or `//./pipe/docker_engine`).
- Linux/macOS local Docker: kind `unix`, address `/var/run/docker.sock`.
- Remote host: `tcp` or `tls` with `host:2376`.

Verified on Windows: double-click installer with both system and portable Node (checksum-verified), UI build,
Desktop/Start Menu shortcuts, first-run setup, one-click Docker Desktop named-pipe discovery from the welcome
screen, a real vulnerability scan with the managed scanner, port-conflict guidance and restart persistence. macOS/Linux native installation uses the same Node code but the tar/launcher path was
not executed in this environment; treat those platforms as untested. Graceful signal handling is shared with
the container path (verified there).

## Compose (local Docker socket)

```bash
cp .env.example .env
# optional: set SETUP_TOKEN; otherwise read it from the logs after first start
docker compose up -d --build
docker compose logs -f docksentinel
```

Open `http://<host>:8080`. The first-run token is printed once as:

```
DockSentinel initial setup token: ...
```

Add an environment in the UI:

- **Kind:** Local Unix socket
- **Address:** `/var/run/docker.sock`

The Compose file mounts the socket read-only, but Docker access is effectively privileged. See
[Security](SECURITY.md#docker-socket-access).

### Socket permissions

The app process runs as `PUID:PGID` (default `10001:10001`). Access to the socket requires membership of
the socket's group:

```bash
stat -c '%g' /var/run/docker.sock
```

Set `DOCKER_GID` in `.env` to that value, then recreate the container. Docker Desktop on Windows/macOS
presents the socket as `root:root` mode `0660`; for local testing use `PUID=10001 PGID=0` (or
`--group-add 0`). On Linux hosts, if the socket is owned by `root:root` with mode `0660` and you do not
want to run with GID 0, use a socket proxy instead. Do not "fix" it by making the socket world-writable.

### Volumes

| Container path | Purpose |
| --- | --- |
| `/data` | `docksentinel.db`, `secret.key`, `trivy-cache/`, `tmp/` scan scratch, `backups/` |
| `/var/run/docker.sock` | Optional local Docker Engine (read-only bind mount) |

The image declares `/data` as a volume. Back up `/data/docksentinel.db` **and** `/data/secret.key`
together.

### Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `DATA_DIR` | `/data` | Do not place on a network filesystem that lacks SQLite locking |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Listener |
| `LOG_LEVEL` | `info` | JSON logs to stdout |
| `TRUST_PROXY` | `false` | Enable only behind a trusted proxy |
| `COOKIE_SECURE` | `auto` | `always` when TLS terminates at a proxy |
| `SETUP_TOKEN` | random | Logged once when unset |
| `DOCKSENTINEL_SECRET_KEY` | generated file | 32 bytes base64/hex; protect and back up |
| `TRIVY_BIN` | `trivy` | Bundled in the production image |
| `TRIVY_CACHE_DIR` | `/data/trivy-cache` | Persistent DB cache |
| `SCAN_TIMEOUT_MS` | `900000` | Per-scan hard timeout |
| `SCAN_MAX_OUTPUT_BYTES` | `100663296` | Report cap |
| `MAX_IMAGE_EXPORT_BYTES` | `8589934592` | Archive cap |
| `IMAGE_EXPORT_TIMEOUT_MS` | `600000` | Export timeout |
| `SCAN_CONCURRENCY` | `2` | Upper bound; UI setting can be lower |
| `KEV_URL` | CISA feed | Override for mirrors/proxies |
| `PUID` / `PGID` | `10001` | Runtime UID/GID; entrypoint chowns `/data` |
| `DOCKER_GID` | `999` | Compose convenience variable for `group_add` |

Operational settings (intervals, thresholds, retention, notifications) are changed in the UI and stored
in SQLite; they survive restarts.

## Remote Docker endpoints

### Mutual TLS (recommended)

Docker's official guidance for protecting the daemon socket is the source of truth; the short version:

1. Create a CA and server/client certificates with the daemon's hostname/IP in the server SAN.
2. Configure the daemon with `tlsverify`, `tlscacert`, `tlscert`, `tlskey` and listen on `2376`.
3. In DockSentinel, add an environment with kind **TCP with TLS and client certificates**, address
   `host:2376`, and paste the CA, client certificate and client key (PEM).
4. Test the connection. Certificate validation is on by default; "skip verify" exists only for
   self-signed lab endpoints on trusted networks.

DockSentinel never gives these credentials to Trivy: images are exported by DockSentinel's own TLS client
and passed to the scanner as a local archive.

### Plain TCP

Plain `tcp://host:2375` is accepted for trusted private networks and is labelled as insecure in the UI.
It must never be exposed to the Internet or an untrusted VLAN.

### Socket proxy (optional hardening)

If you do not want to mount the Docker socket into DockSentinel, run a read-only socket proxy and add the
proxy's TCP port as a **TCP** environment. DockSentinel only calls these endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/_ping` | connectivity |
| `/version` | daemon version |
| `/containers/json?all=1` | container inventory |
| `/images/json` | image inventory |
| `/images/{id}/get` | image archive for scanning |

A proxy configuration allowing only those read operations (for example `tecnativa/docker-socket-proxy`
with `CONTAINERS=1`, `IMAGES=1`, `INFO=1` and all other switches off) is sufficient. Verify the proxy's
current allowlist before relying on it; the proxy itself is privileged infrastructure.

### Optional socket-proxy Compose example

Instead of mounting the socket into DockSentinel, run a read-only proxy on an internal network. The exact
environment variable names depend on the proxy image and version; this example uses
`tecnativa/docker-socket-proxy` and must be verified before production use.

```yaml
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:0.3
    restart: unless-stopped
    environment:
      CONTAINERS: '1'   # /containers/json
      IMAGES: '1'       # /images/json and /images/{id}/get
      INFO: '1'         # /version, /_ping
      POST: '0'
      EXEC: '0'
      BUILD: '0'
      COMMIT: '0'
      VOLUMES: '0'
      NETWORKS: '0'
      AUTH: '0'
      SECRETS: '0'
      SWARM: '0'
      SYSTEM: '0'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [proxy]

  docksentinel:
    # ...as above, but without the docker.sock volume...
    networks: [proxy, default]

networks:
  proxy:
    internal: true
```

Then add the environment in DockSentinel as kind **TCP**, address `docker-proxy:2375`. Confirm the proxy
allows the five read endpoints listed above. Treat the proxy container as privileged infrastructure and keep
it off any external network.

## Reverse proxy and TLS

Example with Caddy:

```caddyfile
docksentinel.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

Example with nginx:

```nginx
server {
  listen 443 ssl http2;
  server_name docksentinel.example.com;
  ssl_certificate     /etc/ssl/fullchain.pem;
  ssl_certificate_key /etc/ssl/privkey.pem;
  client_max_body_size 1m;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Then set `TRUST_PROXY=true` and `COOKIE_SECURE=always` for DockSentinel. Without `TRUST_PROXY`, the app
ignores forwarded headers, which is safer than trusting arbitrary clients.

Do not expose DockSentinel's port directly to the Internet without authentication in front of it; the app
has its own login, but a VPN or authenticated proxy is still recommended for a security console.

## Published image

`ghcr.io/luriot/docksentinel` is public and published for `linux/amd64` and `linux/arm64` with tags
`latest`, `main` and `sha-<commit>`, BuildKit SBOM/provenance, and a signed GitHub provenance attestation:

```bash
docker pull ghcr.io/luriot/docksentinel:latest
gh attestation verify oci://ghcr.io/luriot/docksentinel:latest -R Luriot/DockSentinel
```

`docker compose up --build` builds from local source instead of pulling. Create a `v*` tag and push it to
publish semver tags.

## Health, shutdown and logs

- Liveness/readiness: `GET /api/health` (no authentication) executes a database query and returns
  `{ "status": "ok", "version": "...", "uptimeSeconds": ... }`.
- The image defines a `HEALTHCHECK` using that endpoint.
- Logs are structured JSON on stdout. Authentication secrets are redacted.
- `SIGTERM` triggers graceful shutdown: stop scheduling, close HTTP, abort in-flight scans (requeued on
  next start), close the database. `tini` forwards signals correctly.

## Upgrades

1. Back up first: `docker exec docksentinel node scripts/backup.ts`.
2. Pull the new image (or rebuild) and recreate the container. Schema migrations run automatically at
   startup in a transaction.
3. Downgrades are not supported by the migration runner: restoring an older image against a newer schema
   is refused. Restore the matching database backup instead.
4. Check `/api/health` and the Settings page (scanner version, schema version) after the upgrade.

## Backup

```bash
docker exec docksentinel node scripts/backup.ts
```

This uses SQLite `VACUUM INTO`, producing a consistent snapshot while the service runs, plus a copy of
`secret.key` when the key is file-based. The output lives in `/data/backups` by default; pass a directory
argument to override:

```bash
docker exec docksentinel node scripts/backup.ts /data/backups/manual
```

Back up the whole `/data` directory if you also want the Trivy cache (optional; it can be re-downloaded).
Treat backups as secrets: they contain encrypted credentials and the key that decrypts them.

## Restore

1. Stop the container.
2. Replace `/data/docksentinel.db` with the backup and restore the matching `secret.key` (or set
   `DOCKSENTINEL_SECRET_KEY` to the key used by that backup).
3. Remove the stale `docksentinel.db-wal` / `docksentinel.db-shm` files if present.
4. Start the container and verify `/api/health`, then sign in.

## Administrator recovery

If the password is lost, run inside the container:

```bash
docker exec -it docksentinel env DOCKSENTINEL_NEW_PASSWORD='a-new-long-password' \
  node scripts/reset-password.ts
```

All sessions are invalidated. This requires filesystem/console access to the container, which already
implies control of the instance.

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| "Trivy unavailable" in Settings | Scanner binary missing from the image or `TRIVY_BIN` wrong. The production image bundles it; local dev needs `trivy` on `PATH`. |
| Scan fails with `db_unavailable` | No vulnerability database in the cache and no outbound HTTPS. Pre-seed `TRIVY_CACHE_DIR` (see [SCANNERS.md](SCANNERS.md#air-gapped--offline-operation)) or allow egress. |
| Scan fails with `image_export_failed` / HTTP 500 | Docker daemon could not export the image (storage pressure, image removed). Retry; check daemon logs. |
| Scan fails with `image_too_large` / output limits | Raise `MAX_IMAGE_EXPORT_BYTES` / `SCAN_MAX_OUTPUT_BYTES` deliberately, or scan a smaller image variant. |
| Environment offline, permission denied on socket | Add the socket GID (`DOCKER_GID` / `--group-add`) or use a socket proxy. |
| TLS endpoint test fails | Certificate/key/CA mismatch, wrong SAN, or verification disabled incorrectly. Check the endpoint address (`host:2376`). |
| Alerts pending with "notifications disabled" | Configure and enable ntfy in Notifications; pending alerts are retried once configured. |
| Alerts failed with HTTP 401/403 | Wrong ntfy token/credentials or topic permissions. Use Test delivery. |
| Login says "Too many attempts" | Per-IP limiter. Wait five minutes; restart clears the in-memory counter. |
| Disk fills during scans | Lower `MAX_IMAGE_EXPORT_BYTES`, reduce concurrency, clean `/data/tmp`, ensure scans are not repeatedly retrying a huge image. Note the Trivy cache can reach ~1–2 GiB after standard scans. |
| Stale results everywhere | Endpoint unreachable or scans failing. Check Environments, Scan activity and scanner database status. |
| UI shows old assets after upgrade | The SPA entry is served with `no-cache`; hard-refresh once if a proxy overrode cache headers. |

## Verifying the production image locally

This was executed on Docker Desktop 4.96.2 / Engine 29.9.2 (linux/amd64) during development:

| Check | Observed result |
| --- | --- |
| Image build (`docker buildx build --platform linux/amd64 --load`) | Succeeded; `docker buildx build --check` reported no warnings |
| Container health | `healthy`; `/api/health` returned 200 |
| Process privileges | PID 1 `tini` root; application ran as UID 10001 (`node src/index.ts`); data owned by 10001 |
| Scanner | Bundled Trivy 0.75.0; database downloaded during the first scan and persisted in the volume |
| Docker discovery | 2 containers / 2 images from the live Docker Desktop engine |
| Real image scan | `nginx:1.19-alpine`: 96 findings (9 critical, 52 high, 29 medium, 6 low, 96 fixable); 14.4 s cold, 0.19 s warm |
| Re-scan stability | Same image ID: 96 open findings, **0 resolved/recreated** |
| Alerting | Grouped ntfy alert for 9 critical/52 high delivered (test notification also delivered) |
| Restart | 371 findings, 3 scans, 3 delivered alerts and the authenticated session persisted |
| Graceful shutdown | `SIGTERM` handled, container exited 0 |
| Interrupted scan | Scan aborted by shutdown was requeued and completed with attempts=2; findings unchanged |

The container was started for that test with the Docker Desktop socket (`PGID=0` so the non-root process
can read `root:root 0660`):

```bash
docker buildx build --platform linux/amd64 --load -t docksentinel:local .
docker run -d --name docksentinel-test \
  -p 18080:8080 \
  -v docksentinel-test-data:/data \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e SETUP_TOKEN=smoke-test-token \
  -e PUID=10001 -e PGID=0 \
  docksentinel:local
```

On Linux or Unraid, replace `PGID=0` with the socket's group
(`stat -c '%g' /var/run/docker.sock`) or use a socket proxy. Repeat the smoke test after changing the
Dockerfile or Trivy version; record the outcome before publishing an image.

The UI was also driven against that live instance with Playwright and rendered correctly
(`test-results/screens/real-overview.png`, `real-vulnerabilities.png`, `real-images.png`).
