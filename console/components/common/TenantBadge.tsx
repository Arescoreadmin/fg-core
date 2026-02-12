export function TenantBadge({ tenantId }: { tenantId?: string }) {
  return (
    <span style={{ border: '1px solid var(--border)', padding: '0.2rem 0.5rem', borderRadius: 8, fontSize: 12 }}>
      Tenant: {tenantId || 'unset'}
    </span>
  );
}
