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

COPY --chown=node:node --from=builder /app/packages/node/auth/dist /app/dist
COPY --chown=node:node --from=builder /app/packages/node/auth/database/migrations /app/database/migrations
COPY --chown=node:node --from=builder /app/packages/node/auth/database/migrations /app/dist/migrations

USER node
EXPOSE 3001

CMD ["node", "--optimize-for-size", "--max-old-space-size=128", "dist/server.mjs"]
