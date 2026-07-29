/**
 * Next.js instrumentation hook — runs once at server startup before any
 * request is handled.  We use it to fail fast on misconfigured production
 * deployments rather than surfacing the problem as a request-time 502/503.
 *
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */
export async function register() {
  // Node.js runtime only — not Edge runtime.
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { validateProductionConfig } = await import('./lib/startup-validation');
    validateProductionConfig();
  }
}
