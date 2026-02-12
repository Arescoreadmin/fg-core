export type ErrorCode =
  | 'AUTH_REQUIRED'
  | 'SCOPE_OR_TENANT_DENIED'
  | 'TENANT_CONTEXT_ERROR'
  | 'NOT_FOUND_OR_FORBIDDEN'
  | 'NOT_FOUND'
  | 'API_ERROR';

export interface AppError extends Error {
  code: ErrorCode;
  status?: number;
  details?: unknown;
}

const TENANT_ERROR_PATTERNS = [/tenant/i, /missing tenant/i, /tenant.*required/i];

function textFromPayload(payload: unknown): string {
  if (!payload) return '';
  if (typeof payload === 'string') return payload;
  if (typeof payload === 'object') {
    const msg = (payload as { detail?: unknown }).detail;
    if (typeof msg === 'string') return msg;
    return JSON.stringify(payload);
  }
  return '';
}

export function mapHttpError(status: number, payload?: unknown, options: { mask404?: boolean } = {}): AppError {
  const message = textFromPayload(payload) || `Request failed with status ${status}`;

  const makeError = (code: ErrorCode): AppError => {
    const error = new Error(message) as AppError;
    error.code = code;
    error.status = status;
    error.details = payload;
    return error;
  };

  if (status === 401) return makeError('AUTH_REQUIRED');
  if (status === 403) return makeError('SCOPE_OR_TENANT_DENIED');
  if (status === 404) return makeError(options.mask404 ? 'NOT_FOUND_OR_FORBIDDEN' : 'NOT_FOUND');

  if (status === 400 && TENANT_ERROR_PATTERNS.some((pattern) => pattern.test(message))) {
    return makeError('TENANT_CONTEXT_ERROR');
  }

  return makeError('API_ERROR');
}

export function toUserMessage(error: unknown): string {
  if (!error || typeof error !== 'object' || !(error instanceof Error)) return 'Unexpected error.';

  const appError = error as AppError;
  switch (appError.code) {
    case 'AUTH_REQUIRED':
      return 'Authentication required. Provide a valid API key.';
    case 'SCOPE_OR_TENANT_DENIED':
      return 'Scope or tenant denied. Verify API key scopes and tenant context.';
    case 'TENANT_CONTEXT_ERROR':
      return 'Tenant context missing or invalid.';
    case 'NOT_FOUND_OR_FORBIDDEN':
      return 'Not found or forbidden for current tenant context.';
    case 'NOT_FOUND':
      return 'Resource not found.';
    default:
      return appError.message || 'Request failed.';
  }
}
