# AGENTS.md

DockSentinel is a Node.js 24.12+ TypeScript/React app that orchestrates Trivy for Docker image
vulnerability monitoring. Preserve the existing architecture, security controls and deployment paths;
do not rebuild the app or replace Trivy with a custom scanner.

## Commands

```bash
npm install
npm run dev                 # backend on :8080
npm run dev:web             # Vite on :5173, proxies /api
npm run typecheck
npm test                    # unit + integration; real Trivy tests skip without a cached DB
npm run test:ui             # run npm run build first if web/dist is stale
npm run build
npm start                   # production UI + API
npm run native:setup        # build UI + install checksum-verified Trivy (Node 24.12+)
npm run native              # native launcher on 127.0.0.1:8080
npm run backup              # VACUUM INTO + key copy
```

Windows users can double-click `Install-DockSentinel.cmd`; it installs a private Node runtime,
verified Trivy and shortcuts. Do not change the Docker image's pinned Trivy version or behaviour
without explicit approval.

## Architecture

- `src/index.ts` — startup, workers, graceful shutdown; `src/startup.ts` — preflight errors.
- `src/api/` — Fastify routes, auth/CSRF, static SPA; `src/api/context.ts` is the service container.
- `src/db/` — `node:sqlite` wrapper and append-only migrations. **Never edit a shipped migration.**
- `src/repo/` — SQL aggregates; `src/domain/` — pure rules/types.
- `src/scanner/` — Trivy adapter/parsing; `src/scan/` — queue, export, retry, lifecycle.
- `src/notify/`, `src/jobs/`, `src/intel/`, `src/discovery.ts`, `src/docker/`.
- `web/src/` — React views/components; build output is `web/dist`, served by the backend.
- `test/` — `node:test`; helpers under `test/helpers/`; Playwright spec under `test/ui/`.
- Dependencies flow `api → services → repo → db`; `domain` stays pure.

Backend TypeScript runs directly with type stripping and `.ts` import specifiers; there is no backend
compile step. Use the built-in `node:sqlite` `DatabaseSync`; avoid native modules and new dependencies
unless clearly justified.

## Non-obvious rules

- Scans export images by immutable image ID, then run `trivy image --input` from the scratch directory
  with a relative archive name. This keeps finding targets stable across rescans.
- Failed, timed-out, malformed or cancelled scans must never resolve findings or look clean.
- Content scans are opt-in and separate: `content_findings`, no vulnerability counters/alerts/image
  status. Never persist, log, return or display raw secret `Match`, code or layer content.
- Docker API access is read-only and privileged. Keep the endpoint allowlist, TLS handling, auth,
  CSRF/Origin checks, encrypted secrets, safe process execution and output caps intact.
- Migrations are append-only; settings are validated in the API before saving.
- Native data lives in a per-user folder; Docker uses `/data`. Never commit `data/`, `.scratch/`,
  `web/dist/`, secrets or test artifacts.
- Do not push, publish, change GitHub settings or trigger GHCR builds without explicit user approval.
- Update README/HANDOFF/docs when behaviour, commands or limitations change.

## Before finishing

Run `npm run typecheck`, `npm test`, `npm run test:ui` and `npm run build` for code changes. For Docker
changes, build and smoke-test the image. State what was actually executed and any platform gaps.
