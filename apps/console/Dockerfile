# Console Dockerfile (production-ready)
# - Multi-stage build: build context is monorepo root so packages/ui is reachable
# - Full deps available for build stage
# - Non-root runtime
# - Standalone output

FROM node:20-alpine AS deps
WORKDIR /app/apps/console

ENV NEXT_TELEMETRY_DISABLED=1

# Install all deps needed to build, including devDependencies
COPY apps/console/package.json apps/console/package-lock.json* ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app/apps/console

ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/apps/console/node_modules ./node_modules
# Copy console source
COPY apps/console/ .
# Copy packages/ui so tsconfig @fg/ui alias (../../packages/ui/src) resolves correctly
COPY packages/ /app/packages/

# Build-time public API base
ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}

# Build in production mode, but with full deps already installed
ENV NODE_ENV=production

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app/apps/console

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 nextjs

COPY --from=builder /app/apps/console/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/apps/console/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/console/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD wget -q -T 2 -O - http://127.0.0.1:3000/api/health >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
