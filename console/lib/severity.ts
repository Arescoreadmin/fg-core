export type Severity = 'ok' | 'info' | 'warning' | 'critical' | 'unknown';

const SEVERITY_MAP: Record<string, Severity> = {
  ok: 'ok',
  pass: 'ok',
  healthy: 'ok',
  verified: 'ok',
  operational: 'ok',
  active: 'ok',
  running: 'ok',
  connected: 'ok',
  info: 'info',
  notice: 'info',
  warning: 'warning',
  degraded: 'warning',
  partial: 'warning',
  unverified: 'critical',
  critical: 'critical',
  error: 'critical',
  fail: 'critical',
  failed: 'critical',
  failure: 'critical',
  unavailable: 'critical',
};

export function mapToSeverity(status: string | null | undefined): Severity {
  if (!status) return 'unknown';
  return SEVERITY_MAP[status.toLowerCase()] ?? 'unknown';
}
