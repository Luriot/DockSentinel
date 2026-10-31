# syntax=docker/dockerfile:1.7

# --- Web build -------------------------------------------------------------------------------
FROM node:24-bookworm-slim AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./web
RUN npx vite build --config web/vite.config.ts

# --- Production dependencies -----------------------------------------------------------------
FROM node:24-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# --- Trivy (pinned separately from the Node runtime) -----------------------------------------
FROM aquasec/trivy:0.75.0 AS trivy

# --- Runtime ---------------------------------------------------------------------------------
FROM node:24-bookworm-slim

LABEL org.opencontainers.image.title="DockSentinel" \
      org.opencontainers.image.description="Docker vulnerability monitoring and alerting, orchestrated with Trivy" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini gosu util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 docksentinel \
 && useradd --system --uid 10001 --gid docksentinel --home-dir /nonexistent --shell /usr/sbin/nologin docksentinel

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
ENV NODE_ENV=production \
    DATA_DIR=/data \
    HOME=/data \
    PORT=8080 \
    HOST=0.0.0.0 \
    LOG_LEVEL=info \
    PUID=10001 \
    PGID=10001

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
COPY --from=web /app/web/dist ./web/dist
COPY docker/entrypoint.sh /usr/local/bin/docksentinel-entrypoint
RUN chmod +x /usr/local/bin/docksentinel-entrypoint \
 && mkdir -p /data \
 && chown -R 10001:10001 /data /app

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/api/health').then((r) => { if (!r.ok) process.exit(1); }).catch(() => process.exit(1));"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docksentinel-entrypoint"]
CMD ["node", "src/index.ts"]
