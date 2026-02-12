'use client';

import { useEffect, useState } from 'react';

export function TenantSwitcher({ defaultTenant }: { defaultTenant?: string }) {
  const [tenant, setTenant] = useState(defaultTenant || '');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const currentTenant = params.get('tenant_id') || defaultTenant || '';
    setTenant(currentTenant);
  }, [defaultTenant]);

  function applyTenant() {
    const params = new URLSearchParams(window.location.search);
    if (tenant) params.set('tenant_id', tenant);
    else params.delete('tenant_id');
    window.location.href = `/dashboard?${params.toString()}`;
  }

  return (
    <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
      <input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="tenant_id" aria-label="tenant_id" />
      <button onClick={applyTenant}>Use tenant</button>
    </div>
  );
}
