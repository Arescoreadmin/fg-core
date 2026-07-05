/**
 * Workspace context utilities — server-safe, no browser APIs.
 * Pure functions only.
 */

export interface WorkspaceContext {
  tenant?: string;
  engagement?: string;
  assessment?: string;
  report?: string;
  finding?: string;
  remediation?: string;
  policy?: string;
  decision?: string;
  timelinePosition?: string;
  framework?: string;
  control?: string;
  evidence?: string;
  customer?: string;
  simulation?: string;
  replay?: string;
}

export type WorkspaceContextKey = keyof WorkspaceContext;

export const WORKSPACE_CONTEXT_KEYS: WorkspaceContextKey[] = [
  'tenant',
  'engagement',
  'assessment',
  'report',
  'finding',
  'remediation',
  'policy',
  'decision',
  'timelinePosition',
  'framework',
  'control',
  'evidence',
  'customer',
  'simulation',
  'replay',
];

/**
 * Parse workspace context from URLSearchParams or a plain Record<string, string>.
 */
export function parseWorkspaceContext(
  params: URLSearchParams | Record<string, string>,
): WorkspaceContext {
  const get = (key: string): string | undefined => {
    if (params instanceof URLSearchParams) {
      return params.get(key) ?? undefined;
    }
    return params[key] ?? undefined;
  };

  const ctx: WorkspaceContext = {};
  for (const key of WORKSPACE_CONTEXT_KEYS) {
    const value = get(key);
    if (value !== undefined && value !== '') {
      ctx[key] = value;
    }
  }
  return ctx;
}

/**
 * Build a URL by appending non-undefined WorkspaceContext values as search params.
 */
export function buildWorkspaceUrl(base: string, context: WorkspaceContext): string {
  const params = contextToParams(context);
  const query = params.toString();
  if (!query) return base;
  return base.includes('?') ? `${base}&${query}` : `${base}?${query}`;
}

/**
 * Merge two WorkspaceContext objects; override values win.
 */
export function mergeWorkspaceContext(
  base: WorkspaceContext,
  override: Partial<WorkspaceContext>,
): WorkspaceContext {
  return { ...base, ...override };
}

/**
 * Convert WorkspaceContext to URLSearchParams, omitting undefined values.
 */
export function contextToParams(context: WorkspaceContext): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of WORKSPACE_CONTEXT_KEYS) {
    const value = context[key];
    if (value !== undefined && value !== '') {
      params.set(key, value);
    }
  }
  return params;
}
