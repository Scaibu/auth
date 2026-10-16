FROM node:26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache bash

COPY shared-infra /app/packages/node/shared-infra
COPY auth /app/packages/node/auth

WORKDIR /app/packages/node/shared-infra
RUN npm install --no-audit --no-fund

WORKDIR /app/packages/node/auth
RUN rm -f package-lock.json && npm install --no-audit --no-fund

RUN npx esbuild src/server.ts \
  --bundle \
  --platform=node \
  --format=esm \
  --external:pg-native \
  --banner:js="import { createRequire } from 'module'; const require = createRequire(import.meta.url);" \
  --outfile=dist/server.mjs

FROM node:26-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001
ENV KEYCLOAK_BASE_URL=http://auth-service-keycloak:8080
ENV KEYCLOAK_ISSUER_URL=http://auth-service-keycloak:8080/realms/llm-observability
ENV KEYCLOAK_REALM=llm-observability
ENV KEYCLOAK_CLIENT_ID=auth-service-admin
ENV MAILER_PROVIDER=mock
ENV AUTH_GEOIP_PROVIDER=http
ENV AUTH_GEOIP_TIMEOUT_MS=1500
ENV AUTH_SECURITY_HEADERS_ENABLED=true
ENV AUTH_WEBHOOK_TOLERANCE_MS=300000
ENV AUTH_WEBHOOK_DEFAULT_RETRIES=5
ENV AUTH_HONEYTOKEN_ENABLED=true
ENV AUTH_HONEYTOKEN_PREFIX=ht_canary_
ENV AUTH_HONEYTOKEN_AUTO_BLOCK_IP=true

COPY --chown=node:node --from=builder /app/packages/node/auth/dist /app/dist
COPY --chown=node:node --from=builder /app/packages/node/auth/database /app/database
COPY --chown=node:node --from=builder /app/packages/node/auth/database/migrations /app/dist/migrations
COPY --chown=node:node --from=builder /app/packages/node/auth/scripts /app/scripts

USER node
EXPOSE 3001

CMD ["node", "--optimize-for-size", "--max-old-space-size=128", "dist/server.mjs"]
