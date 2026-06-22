/**
 * Console configuration
 */

export const config = {
  // API base URL for admin-gateway
  apiUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:18001',

  // App name
  appName: 'FrostGate Console',

  // Version
  version: '0.1.0',
};

/**
 * Build API URL for a given path
 */
export function apiUrl(path: string): string {
  const base = config.apiUrl.replace(/\/$/, '');
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${base}${cleanPath}`;
}
