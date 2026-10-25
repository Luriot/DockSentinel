# HTTP API

The UI is a client of this API. There is a single administrator account, no API keys, and no unauthenticated
administrative endpoints. All JSON responses use camelCase. Errors have the shape:

```json
{ "error": { "code": "invalid_request", "message": "Human readable explanation" } }
```

## Authentication

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Public liveness/readiness; runs a database query |
| `GET` | `/api/auth/session` | Setup state and, when signed in, user + CSRF token |
| `POST` | `/api/auth/setup` | First-run account creation (`setupToken`, `username`, `password`) |
| `POST` | `/api/auth/login` | `{ username, password }`; sets the `ds_session` cookie |
| `POST` | `/api/auth/logout` | Requires session + `X-CSRF-Token`; deletes the session |
| `POST` | `/api/auth/password` | Requires session + `X-CSRF-Token`; `{ currentPassword, newPassword }` |

- Session cookie: `ds_session`, `HttpOnly`, `SameSite=Strict`, 7-day sliding expiry, `Secure` on HTTPS.
- Mutating requests (`POST`, `PATCH`, `PUT`, `DELETE`) must send `X-CSRF-Token` with the value from
  `/api/auth/session`. Origin is checked when provided.
- Login and setup are rate limited per IP (10 attempts per 5 minutes → `429`).
- Unauthenticated `/api/*` requests return `401`, including unknown routes.

## Read endpoints

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/overview` | Dashboard aggregates, top findings, recent activity, environments |
| `GET` | `/api/environments` | Docker host list with status and counts |
| `GET` | `/api/environments/detect` | Probes local Docker Desktop/named-pipe/Unix socket candidates for the welcome screen |
| `GET` | `/api/images` | Filters: `q`, `envId`, `minSeverity=critical\|high`, `neverScanned`, `stale`, `page`, `pageSize` |
| `GET` | `/api/images/:imageId` | Image inventory, containers, findings, counts, scans, events |
| `PATCH` | `/api/images/:imageId` | Body `{ "scanExcluded": true\|false }`; excludes the image from scheduled and manual scans (existing findings stay) |
| `GET` | `/api/containers` | Filters: `q`, `envId`, `status=running\|stopped\|all`, `exposure`, `includeRemoved`, paging |
| `GET` | `/api/containers/:environmentId/:id` | Container detail, image, findings, scans |
| `GET` | `/api/findings` | Filters: `q`, `severity` (comma list), `envId`, `imageId`, `kev`, `fixable`, `running`, `state=open\|resolved\|all`, `includeSuppressed`, `includeKernel` (kernel/header packages hidden by default), paging |
| `GET` | `/api/findings/:id` | Finding detail, image, events, scans |
| `GET` | `/api/findings/export` | CSV/JSON export with the same finding filters (`format=csv\|json`) |
| `GET` | `/api/findings/grouped` | Same filters as `/api/findings`; one row per CVE + package with `images`, `findings`, `targets`, `fixable`, `kev` |
| `GET` | `/api/content-findings` | Opt-in misconfiguration/secret metadata; filters `kind`, `severity`, `state`, `imageId`, `q`, paging. Never contains secret values |
| `GET` | `/api/scans` | Filters: `status`, `kind=vulnerability\|content`, `imageId`, `envId`, paging |
| `GET` | `/api/scans/:id` | Scan detail |
| `GET` | `/api/notifications` | ntfy public settings, alert history, delivery counts (`status`, `kind`, paging) |
| `GET` | `/api/settings` | Public settings, KEV status, scanner status |
| `GET` | `/api/system` | Version, runtime limits, activity, scanner/KEV status |
| `GET` | `/api/system/status` | Docker host health, scanner/KEV, disk, backups and app status |

Image IDs contain `:`. Encode them in the path (`sha256%3A…`); Fastify decodes them.

`POST /api/images/:imageId/content-scan` takes no parameters. If a client sets
`Content-Type: application/json`, send an empty object (`{}`) to satisfy the JSON body parser.

## Mutating endpoints

| Method | Path | Body |
| --- | --- | --- |
| `POST` | `/api/environments` | `name`, `kind` (`unix`/`tcp`/`tls`), `address`, optional TLS PEM fields, intervals, thresholds, enabled flags |
| `POST` | `/api/environments/local` | One-click local Docker: probes candidates, creates/reuses `This computer`, runs discovery. `409` when no Docker is reachable |
| `PATCH` | `/api/environments/:id` | Same fields, all optional. Unknown fields are stripped |
| `DELETE` | `/api/environments/:id` | Refused while a scan for that endpoint is queued/running |
| `POST` | `/api/environments/:id/test` | Connectivity test; returns `{ ok, message, containers, images }` |
| `POST` | `/api/environments/:id/discover` | Runs discovery synchronously; `502` when the endpoint is unreachable |
| `POST` | `/api/images/:imageId/scan` | `{ profile: "quick"\|"standard" }`; `409` if a scan is already active |
| `POST` | `/api/images/:imageId/content-scan` | Opt-in misconfiguration/secret scan; `409` if disabled or a scan is active |
| `POST` | `/api/scans` | `{ imageId, profile?, kind? }`; queues a manual vulnerability or content scan |
| `POST` | `/api/scans/:id/cancel` | Cancels a queued/running scan |
| `POST` | `/api/scans/scan-all` | Queues a standard scan for all known images (`{ profile?: "quick"\|"standard" }`) |
| `POST` | `/api/notifications/test` | Sends a test notification with the saved configuration |
| `POST` | `/api/kev/sync` | Synchronises the CISA KEV catalogue (may take a few seconds) |
| `PATCH` | `/api/findings/:id/triage` | `{ status: "none"\|"acknowledged"\|"ignored"\|"false_positive", note? }` |
| `PATCH` | `/api/settings` | Any subset of settings, including nested `ntfy` |
| `POST` | `/api/system/backup` | Creates a consistent database snapshot in `DATA_DIR/backups` |
| `POST` | `/api/system/restore` | `{ name }` stages a backup for restore on the next restart |
| `POST` | `/api/system/update-check` | Checks the latest GitHub release |

### Settings payload

Top-level settings: `scanConcurrency`, `discoveryIntervalMinutes`, `defaultQuickIntervalHours`,
`defaultStandardIntervalHours`, `freshnessHours`, `minAlertSeverity`, `alertOnNew`, `alertOnResolved`,
`alertOnKev`, `alertOnScanFailure`, `alertOnStale`, `scanFailureRetries`, `scanOnDiscovery`,
`retentionScansDays`, `retentionAlertsDays`, `retentionResolvedFindingsDays`, `retentionEventsDays`,
`publicUrl`, `kevEnabled`, `misconfigScanEnabled`, `secretScanEnabled`.

`ntfy`: `enabled`, `baseUrl`, `topic`, `priority` (`min|low|default|high|urgent|max`), `tags`,
`authType` (`none|basic|token`), `username`, `token`, `password`.

Secret semantics:

- Omit `token`/`password` to keep the stored value.
- Send a string to replace it.
- Send `null` to clear it.

Secrets are never returned; responses include `hasToken` / `hasPassword` booleans. Enabling notifications
requires a valid base URL, a topic matching `[-_A-Za-z0-9]{1,64}` and credentials when an auth type is set.

## Example

```bash
BASE=http://127.0.0.1:8080

# Sign in and capture the session cookie + CSRF token
curl -s -c cookies.txt -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"correct-horse-battery"}'

CSRF=$(curl -s -b cookies.txt "$BASE/api/auth/session" | node -pe 'JSON.parse(require("fs").readFileSync(0,"utf8")).csrfToken')

# Queue a quick scan
curl -s -b cookies.txt -X POST "$BASE/api/images/sha256%3A<64-hex>/scan" \
  -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"profile":"quick"}'

# List open critical findings
curl -s -b cookies.txt "$BASE/api/findings?severity=CRITICAL&state=open&pageSize=50"
```

## Pagination

List endpoints return `{ items, total, page, pageSize }`; page size is capped at 100 (50 for alert
history). Findings responses also include `counts` for the current filter.

## Compatibility

This API is versionless and intended for DockSentinel's own UI. Treat it as unstable until a versioned
contract is added.
