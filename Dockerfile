FROM node:26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache bash

COPY shared-infra /app/packages/node/shared-infra
COPY auth /app/packages/node/auth

WORKDIR /app/packages/node/shared-infra
RUN npm install --no-audit --no-fund

WORKDIR /app/packages/node/auth
RUN npm install --no-audit --no-fund

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
ENV AUTH_BREACHED_PASSWORD_ENABLED=true
ENV AUTH_BREACHED_PASSWORD_BASE_URL=https://api.pwnedpasswords.com/range
ENV AUTH_BREACHED_PASSWORD_TIMEOUT_MS=1500
ENV AUTH_BREACHED_PASSWORD_USER_AGENT=llm-observability-auth/1.0.0
ENV AUTH_GEOIP_PROVIDER=http
ENV AUTH_GEOIP_TIMEOUT_MS=1500
ENV MAILER_PROVIDER=mock
ENV AUTH_SECURITY_HEADERS_ENABLED=true
ENV AUTH_MFA_ISSUER=LLMObservability
ENV AUTH_OIDC_ISSUER=http://localhost:3001
ENV AUTH_OIDC_CODE_TTL_MS=300000
ENV AUTH_OIDC_TOKEN_TTL_SECONDS=3600
ENV AUTH_SAML_SP_ENTITY_ID=http://localhost:3001/api/v1/auth/saml/metadata
ENV AUTH_SAML_ACS_URL=http://localhost:3001/api/v1/auth/saml/acs
ENV AUTH_SAML_CLOCK_SKEW_MS=120000
ENV AUTH_SAML_RELAY_STATE_TTL_MS=300000
ENV AUTH_PASSWORD_HISTORY_LIMIT=10
ENV AUTH_WEBAUTHN_RP_ID=localhost
ENV AUTH_WEBAUTHN_RP_NAME="Observability Cloud"
ENV AUTH_WEBAUTHN_ORIGIN=http://localhost:3001
ENV AUTH_WEBAUTHN_CHALLENGE_TTL_MS=300000
ENV AUTH_WEBHOOK_TOLERANCE_MS=300000
ENV AUTH_WEBHOOK_DEFAULT_RETRIES=5

COPY --chown=node:node --from=builder /app/packages/node/auth/dist /app/dist
COPY --chown=node:node --from=builder /app/packages/node/auth/database /app/database
COPY --chown=node:node --from=builder /app/packages/node/auth/database/migrations /app/dist/migrations
COPY --chown=node:node --from=builder /app/packages/node/auth/scripts /app/scripts

USER node
EXPOSE 3001

CMD ["node", "--optimize-for-size", "--max-old-space-size=128", "dist/server.mjs"]
