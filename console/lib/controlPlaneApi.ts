/**
 * controlPlaneApi.ts — API client for FrostGate Control Plane.
 *
 * All requests are proxied through the Next.js API route at /api/core/.
 * No credentials are ever sent in URL query params.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ModuleState = 'starting' | 'ready' | 'degraded' | 'failed' | 'stopped' | 'stale';
export type DepStatus = 'ok' | 'degraded' | 'failed' | 'unknown';
export type LockerState = 'active' | 'paused' | 'quarantined' | 'restarting' | 'stopped' | 'unknown';

export interface DependencyProbe {
  name: string;
  status: DepStatus;
  latency_ms: number | null;
  measured_at_ts: string | null;
  last_check_ts: string | null;
  timeout_ms: number | null;
  error_code: string | null;
}

export interface ModuleSummary {
  module_id: string;
  name: string;
  version: string;
  commit_hash: string;
  build_timestamp: string;
  node_id: string;
  state: ModuleState;
  last_state_change_ts: string;
  health_summary: string;
  last_error_code: string | null;
  breaker_state: string | null;
  queue_depth: number | null;
  registered_at: string;
  last_seen_ts: string;
  uptime_seconds: number;
  tenant_id: string | null;
  dependency_summary: Record<string, DepStatus>;
}

export interface ModuleListResponse {
  modules: ModuleSummary[];
  total: number;
  tenant_scope: string;
  is_global_admin: boolean;
}

export interface DependencyResponse {
  module_id: string;
  dependencies: Record<string, DependencyProbe>;
  dependency_count: number;
}

export interface BootStage {
  stage_name: string;
  status: 'pending' | 'in_progress' | 'ok' | 'failed' | 'skipped';
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  error_code: string | null;
  error_detail_redacted: string | null;
}

export interface BootTraceResponse {
  module_id: string;
  stages: BootStage[];
  stage_order: string[];
  summary: {
    module_id: string;
    total_stages: number;
    completed_stages: number;
    failed_stages: string[];
    is_ready: boolean;
  };
}

export interface LockerRecord {
  locker_id: string;
  tenant_id: string;
  state: LockerState;
  version: string;
  last_heartbeat_ts: string;
  last_state_change_ts: string;
  last_error_code: string | null;
}

export interface LockersResponse {
  lockers: LockerRecord[];
  total: number;
}

export interface LockerCommandResult {
  ok: boolean;
  command_id: string;
  locker_id: string;
  tenant_id: string;
  command: string;
  error_code: string | null;
  error_message: string | null;
  idempotent: boolean;
}

export interface ControlEvent {
  event_instance_id: string;
  content_hash: string;
  event_type: string;
  module_id: string;
  tenant_id: string;
  timestamp: string;
  seq: number;
  payload: Record<string, unknown>;
}

export interface AuditResponse {
  events: ControlEvent[];
  total: number;
  tenant_scope: string;
  since: string | null;
}

export interface DependencyMatrixResponse {
  matrix: Array<{
    module_id: string;
    module_name: string;
    state: ModuleState;
    tenant_id: string | null;
    [dep: string]: unknown;
  }>;
  module_count: number;
  tenant_scope: string;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function cpRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type') && init.method && init.method !== 'GET') {
    headers.set('Content-Type', 'application/json');
  }

  const resp = await fetch(`/api/core${path}`, {
    ...init,
    headers,
    cache: 'no-store',
  });

  const text = await resp.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!resp.ok) {
    const err = payload as { error?: { code?: string; message?: string } };
    const msg = err?.error?.message ?? `HTTP ${resp.status}`;
    const code = err?.error?.code ?? 'CP_ERROR';
    const error = new Error(msg) as Error & { code: string; status: number };
    error.code = code;
    error.status = resp.status;
    throw error;
  }

  return payload as T;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export function listModules(): Promise<ModuleListResponse> {
  return cpRequest('/control-plane/modules');
}

export function getModuleDependencies(moduleId: string): Promise<DependencyResponse> {
  return cpRequest(`/control-plane/modules/${encodeURIComponent(moduleId)}/dependencies`);
}

export function getBootTrace(moduleId: string): Promise<BootTraceResponse> {
  return cpRequest(`/control-plane/modules/${encodeURIComponent(moduleId)}/boot-trace`);
}

export function listLockers(): Promise<LockersResponse> {
  return cpRequest('/control-plane/lockers');
}

export function getDependencyMatrix(): Promise<DependencyMatrixResponse> {
  return cpRequest('/control-plane/dependency-matrix');
}

export function getAuditLog(since?: string, limit = 100): Promise<AuditResponse> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (since) params.set('since', since);
  return cpRequest(`/control-plane/audit?${params.toString()}`);
}

export function lockerCommand(
  lockerId: string,
  command: 'restart' | 'pause' | 'resume' | 'quarantine',
  reason: string,
  idempotencyKey: string,
): Promise<LockerCommandResult> {
  return cpRequest(`/control-plane/lockers/${encodeURIComponent(lockerId)}/${command}`, {
    method: 'POST',
    body: JSON.stringify({ reason, idempotency_key: idempotencyKey }),
  });
}

// ---------------------------------------------------------------------------
// WebSocket event stream
// ---------------------------------------------------------------------------

export interface EventStreamOptions {
  onEvent: (event: ControlEvent) => void;
  onConnect?: () => void;
  onDisconnect?: (reason?: string) => void;
  onError?: (err: Event) => void;
}

export function connectEventStream(opts: EventStreamOptions): () => void {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/api/core/control-plane/events`;

  let ws: WebSocket | null = null;
  let closed = false;
  let pingInterval: ReturnType<typeof setInterval> | null = null;

  function connect() {
    if (closed) return;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      opts.onConnect?.();
      pingInterval = setInterval(() => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send('ping');
        }
      }, 30_000);
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data as string);
        if (data?.type === 'pong') return;
        opts.onEvent(data as ControlEvent);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onerror = (err) => {
      opts.onError?.(err);
    };

    ws.onclose = (evt) => {
      if (pingInterval) clearInterval(pingInterval);
      opts.onDisconnect?.(evt.reason);
      // Reconnect after 3 seconds (unless explicitly closed)
      if (!closed) {
        setTimeout(connect, 3_000);
      }
    };
  }

  connect();

  return () => {
    closed = true;
    if (pingInterval) clearInterval(pingInterval);
    ws?.close(1000, 'client closed');
  };
}
