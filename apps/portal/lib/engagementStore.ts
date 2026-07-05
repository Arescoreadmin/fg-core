/**
 * SSR-safe localStorage helpers for persisting the active engagement across
 * portal pages. All writes are no-ops on the server.
 *
 * Security contract: this is a UX hint only — not authoritative.
 * Every portalApi call is session-authorized at the BFF; invalid or stale
 * engagement IDs fail closed with 403/404 before any data is returned.
 * This value must never be used to grant access or skip an API call.
 */

const KEY = 'fg_portal_eid';

export function getStoredEngagementId(): string {
  if (typeof window === 'undefined') return '';
  try {
    // UX hint only — not authoritative. BFF validates engagement access via server session.
    return localStorage.getItem(KEY) ?? '';
  } catch {
    return '';
  }
}

export function setStoredEngagementId(id: string): void {
  if (typeof window === 'undefined') return;
  try {
    if (id) {
      localStorage.setItem(KEY, id);
    } else {
      localStorage.removeItem(KEY);
    }
  } catch {
    // Private browsing or storage quota exceeded
  }
}
