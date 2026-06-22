'use client';

import { useRouter } from 'next/navigation';

export function LogoutButton() {
  const router = useRouter();

  async function handleLogout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
    router.refresh();
  }

  return (
    <button
      type="button"
      onClick={handleLogout}
      className="px-2.5 py-1 rounded text-xs text-muted hover:text-foreground hover:bg-surface-2 transition-colors"
    >
      Sign out
    </button>
  );
}
