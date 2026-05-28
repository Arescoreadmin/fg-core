/**
 * SSR-safe localStorage helpers for persisting the active engagement across
 * portal pages. All writes are no-ops on the server.
 */

const KEY = 'fg_portal_eid';

export function getStoredEngagementId(): string {
  if (typeof window === 'undefined') return '';
  return localStorage.getItem(KEY) ?? '';
}

export function setStoredEngagementId(id: string): void {
  if (typeof window === 'undefined') return;
  if (id) {
    localStorage.setItem(KEY, id);
  } else {
    localStorage.removeItem(KEY);
  }
}
