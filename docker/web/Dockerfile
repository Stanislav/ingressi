# syntax=docker/dockerfile:1.6

FROM docker.io/oven/bun:1-slim AS base
WORKDIR /app

FROM base AS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY package.json bun.lock ./
# --ignore-scripts skips native addon compilation (better-sqlite3 is a test-only devDep;
# production uses bun's built-in bun:sqlite which needs no compilation)
RUN bun install --frozen-lockfile --ignore-scripts

# Litestream (github.com/benbjohnson/litestream, Apache-2.0) replicates the
# SQLite database to S3-compatible storage in a high availability cluster
# (ee/docs/high-availability.md); it only runs when HA_ENABLED is set. A
# pinned release, checked against its published SHA-256 before use.
FROM base AS litestream
ARG TARGETARCH
ARG LITESTREAM_VERSION=0.5.17
ARG LITESTREAM_SHA256_AMD64=cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d
ARG LITESTREAM_SHA256_ARM64=f8ca4a050095c1efbda2c4365172e61bf9d955ea0d9ac42f448b52e51819baa5
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) asset="litestream-${LITESTREAM_VERSION}-linux-x86_64.tar.gz"; sum="${LITESTREAM_SHA256_AMD64}" ;; \
      arm64) asset="litestream-${LITESTREAM_VERSION}-linux-arm64.tar.gz"; sum="${LITESTREAM_SHA256_ARM64}" ;; \
      *) echo "No Litestream release for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/litestream.tar.gz \
      "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/${asset}"; \
    echo "${sum}  /tmp/litestream.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/litestream; \
    tar -xzf /tmp/litestream.tar.gz -C /opt/litestream litestream LICENSE; \
    chmod 0755 /opt/litestream/litestream; \
    rm /tmp/litestream.tar.gz

FROM base AS builder
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATABASE_PATH=/tmp/build.db
ENV DATABASE_URL=file:/tmp/build.db
# Application version baked into the UI/OpenAPI spec at build time (issue #259).
# Set by CI to the git tag (without the leading v) for release builds, or to
# the git commit SHA for non-release builds; when unset, next.config.mjs
# resolves it from git and finally falls back to the package.json version.
ARG APP_VERSION
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN bun run build && rm -f /tmp/build.db
# The high availability supervisor (ee/high-availability/cluster), one file
# started by the entrypoint when HA_ENABLED is set.
RUN bun build ee/high-availability/cluster/main.ts --target=bun --outfile=/app/ha-dist/supervisor.js
# The SQLite to PostgreSQL copy (documentation/postgresql.md), one file run
# with the web container stopped:
#   docker compose run --rm --entrypoint bun web db-tools/copy-sqlite-to-postgres.js
# pg's optional native and Cloudflare bindings are never loaded on Bun.
RUN bun build scripts/db/copy-sqlite-to-postgres.ts --target=bun \
      --external pg-native --external pg-cloudflare \
      --outfile=/app/db-tools/copy-sqlite-to-postgres.js
# Break-glass changes from the host, on SQLite or PostgreSQL
# (documentation/mfa.md, ee/docs/sso-enforcement.md), with the web container
# running:
#   docker compose exec web bun db-tools/break-glass.js remove-mfa-policy
RUN bun build scripts/db/break-glass.ts --target=bun \
      --external pg-native --external pg-cloudflare \
      --outfile=/app/db-tools/break-glass.js

FROM base AS runner
ARG PUID=10001
ARG PGID=10001

ENV NODE_ENV=production
ENV PORT=3000
# Next.js leaves SIGTERM and SIGINT to the application, which exits once its
# shutdown work finished (src/lib/shutdown.ts): a PostgreSQL replica hands
# the lead over and records that it stopped, metered API usage is written.
ENV NEXT_MANUAL_SIG_HANDLE=true
# @coinbase/cdp-sdk (x402's facilitator authentication) reports usage and errors to Coinbase unless these are "true".
ENV DISABLE_CDP_USAGE_TRACKING=true
ENV DISABLE_CDP_ERROR_REPORTING=true
WORKDIR /app

RUN (getent group ${PGID} && groupdel $(getent group ${PGID} | cut -d: -f1) || true) && \
    (getent passwd ${PUID} && userdel $(getent passwd ${PUID} | cut -d: -f1) || true) && \
    groupadd -g ${PGID} nodejs && \
    useradd -r -u ${PUID} -g nodejs nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json

COPY --from=builder --chown=nextjs:nodejs /app/.next/server/instrumentation.js ./.next/server/instrumentation.js
COPY --from=builder --chown=nextjs:nodejs /app/.next/server/instrumentation ./.next/server/instrumentation
COPY --from=builder --chown=nextjs:nodejs /app/.next/server/chunks/ ./.next/server/chunks/
COPY --from=builder --chown=nextjs:nodejs /app/drizzle ./drizzle
COPY --from=builder --chown=nextjs:nodejs /app/drizzle-pg ./drizzle-pg
COPY --from=builder --chown=nextjs:nodejs /app/ha-dist/supervisor.js ./ha/supervisor.js
COPY --from=builder --chown=nextjs:nodejs /app/db-tools ./db-tools
COPY --from=litestream /opt/litestream/litestream /usr/local/bin/litestream
COPY --from=litestream /opt/litestream/LICENSE /usr/share/doc/litestream/LICENSE

RUN mkdir -p /app/data && chown -R nextjs:nodejs /app/data

# Shared volume for the custom ACME CA root PEM (issue #192). The web container
# writes it here; Caddy mounts the same volume read-only. Mode 0777 so it stays
# writable regardless of which container (with differing UIDs) initializes the
# named volume first. The file only ever holds a public CA certificate.
RUN mkdir -p /acme-ca && chmod 0777 /acme-ca

COPY --chown=nextjs:nodejs docker/web/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000
USER nextjs
ENTRYPOINT ["/entrypoint.sh"]
