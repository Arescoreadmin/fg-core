/**
 * Canonical resolver for the internal gateway secret during the R6 staged migration.
 *
 * FG_ADMIN_GATEWAY_TOKEN — TypeScript-side preferred legacy name (Vercel dashboard var).
 * FG_INTERNAL_AUTH_SECRET — the operational secret set in Docker and CI environments.
 * FG_INTERNAL_TOKEN — legacy compat alias.
 *
 * Remove all legacy fallbacks in Deploy 3 once every environment has FG_INTERNAL_GATEWAY_SECRET.
 */
export function internalGatewaySecret(): string {
  return (
    process.env.FG_INTERNAL_GATEWAY_SECRET ||
    process.env.FG_ADMIN_GATEWAY_TOKEN ||
    process.env.FG_INTERNAL_AUTH_SECRET ||
    process.env.FG_INTERNAL_TOKEN ||
    ''
  ).trim();
}
