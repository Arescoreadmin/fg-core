const BASE = '/api/core/governance/graph';

export interface GraphNode {
  node_id: string;
  tenant_id: string;
  node_type: string;
  entity_id: string;
  entity_type: string;
  label: string;
  properties: Record<string, unknown>;
  tags: string[];
  trust_score: number;
  degree_centrality: number;
  centrality_rank: number | null;
  confidence: number;
  source_ref: string;
  engagement_id: string | null;
  snapshot_id: string | null;
  derived_at: string;
}

export interface GraphEdge {
  edge_id: string;
  tenant_id: string;
  edge_type: string;
  source_node_id: string;
  target_node_id: string;
  weight: number;
  confidence: number;
  properties: Record<string, unknown>;
  source_ref: string;
  engagement_id: string | null;
  snapshot_id: string | null;
  derived_at: string;
}

export interface NodeDetailResponse {
  node: GraphNode;
  neighbors: GraphNode[];
}

export interface TraversalResponse {
  root_node_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  max_depth_reached: number;
  truncated: boolean;
}

export interface AnomalyResponse {
  anomaly_id: string;
  tenant_id: string;
  pattern_id: string;
  description: string;
  severity: string;
  node_ids: string[];
  edge_ids: string[];
  snapshot_id: string;
  detected_at: string;
  resolved_at: string | null;
  is_active: boolean;
}

export interface LineageChainEntry {
  node: GraphNode;
  edge: GraphEdge | null;
}

export interface LineageResponse {
  origin_node_id: string;
  chain: LineageChainEntry[];
  depth: number;
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  by_node_type: Record<string, number>;
  by_edge_type: Record<string, number>;
  top_centrality_nodes: Array<{
    node_id: string;
    label: string;
    node_type: string;
    degree_centrality: number;
  }>;
  orphaned_nodes: number;
  trust_score_distribution: Record<string, number>;
  last_snapshot: {
    snapshot_id: string;
    snapshot_seq: number;
    built_at: string;
    triggered_by: string;
    nodes_upserted: number;
    edges_upserted: number;
    anomalies_detected: number;
  } | null;
  anomaly_count: number;
}

export interface CoverageResponse {
  framework: string;
  total_controls: number;
  covered_controls: number;
  coverage_pct: number;
  missing: string[];
  covered: string[];
}

export interface PathResponse {
  found: boolean;
  nodes: GraphNode[];
}

export interface GraphBuildResult {
  snapshot_id: string;
  snapshot_seq: number;
  tenant_id: string;
  nodes_upserted: number;
  edges_upserted: number;
  nodes_deleted: number;
  edges_deleted: number;
  anomalies_detected: number;
  triggered_by: string;
  built_at: string;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new Error(await res.text());
  }
  return res.json() as Promise<T>;
}

function buildQuery(params: Record<string, string | number | boolean | undefined>): string {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== '');
  if (entries.length === 0) return '';
  return '?' + entries.map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join('&');
}

export async function listNodes(params?: {
  node_type?: string;
  limit?: number;
  offset?: number;
}): Promise<GraphNode[]> {
  const q = buildQuery(params ?? {});
  return request<GraphNode[]>(`/nodes${q}`);
}

export async function getNode(nodeId: string, direction?: string): Promise<NodeDetailResponse> {
  const q = buildQuery({ direction });
  return request<NodeDetailResponse>(`/nodes/${nodeId}${q}`);
}

export async function listEdges(params?: {
  edge_type?: string;
  source_node_id?: string;
  target_node_id?: string;
  limit?: number;
  offset?: number;
}): Promise<GraphEdge[]> {
  const q = buildQuery(params ?? {});
  return request<GraphEdge[]>(`/edges${q}`);
}

export async function traverse(
  fromNode: string,
  options?: { max_depth?: number; edge_types?: string; direction?: string },
): Promise<TraversalResponse> {
  const q = buildQuery({ from_node: fromNode, ...(options ?? {}) });
  return request<TraversalResponse>(`/traverse${q}`);
}

export async function getLineage(nodeId: string, maxDepth?: number): Promise<LineageResponse> {
  const q = buildQuery({ max_depth: maxDepth });
  return request<LineageResponse>(`/nodes/${nodeId}/lineage${q}`);
}

export async function getStats(): Promise<GraphStats> {
  return request<GraphStats>('/stats');
}

export async function getCoverage(framework?: string): Promise<CoverageResponse> {
  const q = buildQuery({ framework });
  return request<CoverageResponse>(`/coverage${q}`);
}

export async function listAnomalies(params?: {
  active_only?: boolean;
  severity?: string;
  limit?: number;
}): Promise<AnomalyResponse[]> {
  const q = buildQuery(params ?? {});
  return request<AnomalyResponse[]>(`/anomalies${q}`);
}

export async function resolveAnomaly(anomalyId: string): Promise<AnomalyResponse> {
  return request<AnomalyResponse>(`/anomalies/${anomalyId}/resolve`, { method: 'POST' });
}

export async function findPath(
  fromNode: string,
  toNode: string,
  maxDepth?: number,
): Promise<PathResponse> {
  const q = buildQuery({ from_node: fromNode, to_node: toNode, max_depth: maxDepth });
  return request<PathResponse>(`/path${q}`);
}

export async function rebuildGraph(triggeredBy?: string): Promise<GraphBuildResult> {
  return request<GraphBuildResult>('/build', {
    method: 'POST',
    body: JSON.stringify({ triggered_by: triggeredBy ?? 'ui' }),
  });
}
