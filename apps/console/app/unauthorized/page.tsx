export default function UnauthorizedPage() {
  return (
    <main className="min-h-screen bg-background px-6 py-24">
      <div className="mx-auto max-w-xl rounded-xl border border-border bg-surface p-8 text-center">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-muted">
          Access Restricted
        </p>
        <h1 className="mt-3 text-2xl font-semibold text-foreground">
          This console surface is not available for your role.
        </h1>
        <p className="mt-3 text-sm text-muted">
          FrostGate separates portal-only, client-console, operator, and platform-internal
          access. Request a role update if you need a different console surface.
        </p>
        <a
          href="/dashboard/executive"
          className="mt-6 inline-flex rounded-md bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90"
        >
          Open an allowed workspace
        </a>
      </div>
    </main>
  );
}
