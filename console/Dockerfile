# Console Dockerfile (production-ready)
# - Multi-stage build
# - Non-root runtime
# - Standalone output
# - Same-origin API by default (/api), so browser access "just works"
# - Build-time args supported, but safe defaults

FROM node:20-alpine AS deps
WORKDIR /app

# Reduce attack surface / improve determinism
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Install deps (prefer lockfile)
COPY package.json package-lock.json* ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# ---- Future-facing config knobs ----
# We default to same-origin /api so the browser never needs Docker DNS.
# If you ever want a different base path, you can override at build time.
ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}

# Make Next build predictable
ENV NODE_ENV=production

# Build (assumes next.config.js outputs standalone)
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Keep runtime env too (useful for server-side routes / logging)
ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}

# Add non-root user
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

# Copy standalone output only
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Minimal, reliable healthcheck (no extra packages assumed beyond BusyBox wget)
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD wget -q -T 2 -O - http://127.0.0.1:3000/api/health >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]