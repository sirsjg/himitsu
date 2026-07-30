# syntax=docker/dockerfile:1.7
FROM node:26-bookworm-slim AS build
# The release workflow passes the tag and short SHA in. There is no .git in the build
# context, so without these the web bundle and API health stamp fall back to "dev".
ARG HIMITSU_VERSION=dev
ARG HIMITSU_COMMIT=unknown
ENV HIMITSU_VERSION=${HIMITSU_VERSION} HIMITSU_COMMIT=${HIMITSU_COMMIT}
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts
RUN npm ci
RUN ./scripts/build-all.sh

FROM build AS production-deps
RUN npm prune --omit=dev

FROM node:26-bookworm-slim AS api
ARG HIMITSU_VERSION=dev
ARG HIMITSU_COMMIT=unknown
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 \
    HIMITSU_VERSION=${HIMITSU_VERSION} HIMITSU_COMMIT=${HIMITSU_COMMIT}
WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=production-deps /app/node_modules ./node_modules
COPY --from=build /app/apps/api ./apps/api
COPY --from=build /app/packages ./packages
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/health/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "apps/api/dist/src/server.js"]

FROM nginx:1.27-alpine AS web
# NGINX_ENTRYPOINT_LOCAL_RESOLVERS makes the entrypoint export NGINX_LOCAL_RESOLVERS from
# /etc/resolv.conf; the envsubst filter admits that name alongside our own while still
# leaving nginx's $uri, $host and $scheme untouched.
ENV HIMITSU_API_UPSTREAM=api:3000 \
    NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1 \
    NGINX_ENVSUBST_FILTER='^(HIMITSU_|NGINX_LOCAL_RESOLVERS)'
COPY deploy/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["wget", "--quiet", "--spider", "http://127.0.0.1:8080/nginx-health"]

FROM postgres:16 AS ops
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY packages/database/migrations /app/packages/database/migrations
COPY deploy/migrate.sh deploy/backup.sh deploy/restore.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/migrate.sh"]
