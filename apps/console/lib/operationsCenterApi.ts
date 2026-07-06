/**
 * Operations Center API — derives all data from authoritative platform state.
 * No mock data. No fabricated metrics. Fail closed.
 *
 * MCIM: OPERATIONS-CENTER
 * Authority: FrostGate Platform
 */

import {
  listDecisions,
  getForensicsEvents,
  getControlTowerSnapshot,
  getStatsSummary,
  getFeedLive,
  getProviderGovernance,
  getChainVerify,
} from './coreApi';
import {
  listAnomalies,
  getStats as getGraphStats,
  getCoverage,
  listNodes,
} from './governanceApi';
import type { DecisionOut } from './coreApi';
import type { ForensicsEvent } from './coreApi';

// ─── Shared primitives ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LoadResult<T> =
  | { ok: true; data: T; authority: string; fetchedAt: string }
  | { ok: false; error: string; authority: string };

// ─── 1. Executive Operations Queue ───────────────────────────────────────────

export interface OperationsQueueItem {
  id: string;
  authority: string;
  severity: Severity;
  title: string;
  summary: string | null;
  owner: string | null;
  policy: string | null;
  control: string | null;
  evidenceCount: number;
  confidence: string | null;
  dueAt: string | null;
  businessImpact: string | null;
  workflowState: string;
  lifecycle: string | null;
  source: string;
  createdAt: string | null;
}

export interface OperationsQueueResult {
  items: OperationsQueueItem[];
  total: number;
  bySeverity: Record<Severity, number>;
}

export async function getOperationsQueue(
  limit = 50,
): Promise<LoadResult<OperationsQueueResult>> {
  const authority = '/decisions';
  try {
    const page = await listDecisions({ limit, offset: 0 });
    const items: OperationsQueueItem[] = page.items.map((d: DecisionOut) => ({
      id: d.id,
      authority: 'FrostGate Decision Engine',
      severity: normaliseSeverity(d.threat_level ?? d.severity),
      title: d.event_type ?? 'Governance Event',
      summary: d.explain_summary ?? null,
      owner: d.owner ? String(d.owner) : null,
      policy: d.policy_id ? String(d.policy_id) : null,
      control: d.control_id ? String(d.control_id) : null,
      evidenceCount: typeof d.evidence_count === 'number' ? d.evidence_count : 0,
      confidence: d.confidence ? String(d.confidence) : null,
      dueAt: d.due_at ? String(d.due_at) : null,
      businessImpact: d.business_impact ? String(d.business_impact) : null,
      workflowState: d.workflow_state ? String(d.workflow_state) : 'open',
      lifecycle: d.lifecycle ? String(d.lifecycle) : null,
      source: d.source ?? 'platform',
      createdAt: d.created_at ?? null,
    }));

    const bySeverity: Record<Severity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const item of items) bySeverity[item.severity]++;

    return {
      ok: true,
      data: { items, total: page.total, bySeverity },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 2. Governance Automation Queue ──────────────────────────────────────────

export type AutomationStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'blocked'
  | 'scheduled'
  | 'approval_required';

export interface AutomationQueueItem {
  id: string;
  status: AutomationStatus;
  title: string;
  origin: string | null;
  policy: string | null;
  evidence: string | null;
  reason: string | null;
  rollbackAvailable: boolean;
  severity: string;
  createdAt: string | null;
}

export interface AutomationQueueResult {
  items: AutomationQueueItem[];
  byStatus: Record<AutomationStatus, number>;
}

export async function getAutomationQueue(
  limit = 40,
): Promise<LoadResult<AutomationQueueResult>> {
  const authority = '/ui/forensics/events';
  try {
    // Fetch broadly — no exact event_type filter because real automation events
    // use prefixed types (automation_pending, automation_running, etc.) not the
    // bare string 'automation'. Filter client-side by prefix instead.
    const page = await getForensicsEvents({ limit });
    const allEvents = page.events.filter(
      (e) => e.event_type?.toLowerCase().startsWith('automation') ||
             e.event_category?.toLowerCase().includes('automation'),
    );

    const items: AutomationQueueItem[] = allEvents.map((e: ForensicsEvent) => ({
      id: String(e.event_id),
      status: deriveAutomationStatus(e),
      title: e.event_type ?? 'Automation Event',
      origin: e.request_path ?? null,
      policy: null,
      evidence: e.request_id ?? null,
      reason: e.reason ?? null,
      rollbackAvailable: !e.success && e.severity !== 'critical',
      severity: e.severity ?? 'info',
      createdAt: e.created_at ?? null,
    }));

    const byStatus: Record<AutomationStatus, number> = {
      pending: 0, running: 0, completed: 0,
      failed: 0, blocked: 0, scheduled: 0, approval_required: 0,
    };
    for (const item of items) {
      if (item.status in byStatus) byStatus[item.status]++;
    }

    return {
      ok: true,
      data: { items, byStatus },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 3. Decision Execution Pipeline ──────────────────────────────────────────

export type PipelineStage =
  | 'detected'
  | 'evaluated'
  | 'policy_matched'
  | 'simulation_completed'
  | 'approval_required'
  | 'approved'
  | 'executing'
  | 'executed'
  | 'verified'
  | 'archived';

export interface PipelineItem {
  id: string;
  stage: PipelineStage;
  confidence: string | null;
  authority: string;
  timestamp: string | null;
  deterministic: boolean;
  eventType: string;
  severity: string;
}

export interface PipelineResult {
  items: PipelineItem[];
  byStage: Partial<Record<PipelineStage, number>>;
}

export async function getDecisionPipeline(
  limit = 30,
): Promise<LoadResult<PipelineResult>> {
  const authority = '/decisions';
  try {
    const page = await listDecisions({ limit, offset: 0 });
    const items: PipelineItem[] = page.items.map((d: DecisionOut) => ({
      id: d.id,
      stage: derivePipelineStage(d),
      confidence: d.confidence ? String(d.confidence) : null,
      authority: 'FrostGate Decision Engine',
      timestamp: d.created_at ?? null,
      deterministic: true,
      eventType: d.event_type ?? 'governance_event',
      severity: d.threat_level ?? d.severity ?? 'info',
    }));

    const byStage: Partial<Record<PipelineStage, number>> = {};
    for (const item of items) {
      byStage[item.stage] = (byStage[item.stage] ?? 0) + 1;
    }

    return {
      ok: true,
      data: { items, byStage },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 4. Operational Risk Heatmap ─────────────────────────────────────────────

export interface RiskCell {
  dimension: string;
  category: string;
  count: number;
  severity: Severity;
  authority: string;
}

export interface RiskHeatmapResult {
  cells: RiskCell[];
  totalAnomalies: number;
  nodeCount: number;
  edgeCount: number;
  frameworkCoverage: number | null;
}

export async function getRiskHeatmap(): Promise<LoadResult<RiskHeatmapResult>> {
  const authority = '/governance/graph/stats + /governance/graph/anomalies';
  try {
    const [stats, anomalies] = await Promise.all([
      getGraphStats(),
      listAnomalies({ active_only: true }),
    ]);

    const cells: RiskCell[] = [];

    // Derive cells from anomaly severities across node types
    const byNodeType = stats.by_node_type ?? {};
    for (const [nodeType, count] of Object.entries(byNodeType)) {
      const nodeAnomalies = anomalies.filter(
        (a) => a.severity === 'critical' || a.severity === 'high',
      ).length;
      cells.push({
        dimension: 'Governance',
        category: nodeType,
        count: count as number,
        severity: nodeAnomalies > 0 ? 'high' : 'low',
        authority: 'Governance Graph',
      });
    }

    // Add anomaly breakdown by severity
    for (const anomaly of anomalies) {
      cells.push({
        dimension: 'Anomaly',
        category: anomaly.pattern_id,
        count: anomaly.node_ids.length,
        severity: normaliseSeverity(anomaly.severity),
        authority: 'Governance Graph Anomaly Engine',
      });
    }

    return {
      ok: true,
      data: {
        cells,
        totalAnomalies: anomalies.length,
        nodeCount: stats.node_count,
        edgeCount: stats.edge_count,
        frameworkCoverage: null,
      },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 5. Evidence Freshness Monitor ───────────────────────────────────────────

export type EvidenceStatus = 'current' | 'stale' | 'missing' | 'expiring' | 'unverified';

export interface EvidenceRecord {
  nodeId: string;
  label: string;
  nodeType: string;
  derivedAt: string;
  trustScore: number;
  confidence: number;
  status: EvidenceStatus;
  ageHours: number | null;
}

export interface EvidenceFreshnessResult {
  records: EvidenceRecord[];
  byStatus: Record<EvidenceStatus, number>;
  averageTrustScore: number | null;
}

export async function getEvidenceFreshness(
  limit = 50,
): Promise<LoadResult<EvidenceFreshnessResult>> {
  const authority = '/governance/graph/nodes';
  try {
    const nodes = await listNodes({ limit });

    const nowMs = new Date(nodes[0]?.derived_at ?? 0).getTime() || 0;
    const records: EvidenceRecord[] = nodes.map((n) => {
      const derivedMs = n.derived_at ? new Date(n.derived_at).getTime() : null;
      const ageHours = derivedMs && nowMs
        ? Math.floor((Date.now() - derivedMs) / 3_600_000)
        : null;
      return {
        nodeId: n.node_id,
        label: n.label,
        nodeType: n.node_type,
        derivedAt: n.derived_at,
        trustScore: n.trust_score,
        confidence: n.confidence,
        status: deriveEvidenceStatus(n.trust_score, ageHours),
        ageHours,
      };
    });

    const byStatus: Record<EvidenceStatus, number> = {
      current: 0, stale: 0, missing: 0, expiring: 0, unverified: 0,
    };
    for (const r of records) byStatus[r.status]++;

    const trustScores = records.map((r) => r.trustScore).filter((s) => s >= 0);
    const averageTrustScore =
      trustScores.length > 0
        ? trustScores.reduce((a, b) => a + b, 0) / trustScores.length
        : null;

    return {
      ok: true,
      data: { records, byStatus, averageTrustScore },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 6. Policy Conflict Center ───────────────────────────────────────────────

export type ConflictType =
  | 'duplicate_policy'
  | 'conflicting_policy'
  | 'overlapping_authority'
  | 'missing_ownership'
  | 'contradicting_requirements'
  | 'dead_policy'
  | 'orphaned_control';

export interface PolicyConflict {
  id: string;
  type: ConflictType;
  description: string;
  severity: Severity;
  nodeIds: string[];
  detectedAt: string;
  resolved: boolean;
}

export interface PolicyConflictResult {
  conflicts: PolicyConflict[];
  byType: Partial<Record<ConflictType, number>>;
  orphanedNodes: number;
}

export async function getPolicyConflicts(): Promise<LoadResult<PolicyConflictResult>> {
  const authority = '/governance/graph/anomalies';
  try {
    const [anomalies, stats] = await Promise.all([
      listAnomalies(),
      getGraphStats(),
    ]);

    const conflicts: PolicyConflict[] = anomalies.map((a) => ({
      id: a.anomaly_id,
      type: mapAnomalyToConflictType(a.pattern_id),
      description: a.description,
      severity: normaliseSeverity(a.severity),
      nodeIds: a.node_ids,
      detectedAt: a.detected_at,
      resolved: !a.is_active,
    }));

    const byType: Partial<Record<ConflictType, number>> = {};
    for (const c of conflicts) {
      byType[c.type] = (byType[c.type] ?? 0) + 1;
    }

    return {
      ok: true,
      data: { conflicts, byType, orphanedNodes: stats.orphaned_nodes },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 7. Governance SLA Monitor ───────────────────────────────────────────────

export interface SLAItem {
  id: string;
  title: string;
  severity: Severity;
  dueAt: string | null;
  createdAt: string | null;
  ageHours: number | null;
  slaBreached: boolean;
  owner: string | null;
}

export interface SLAResult {
  items: SLAItem[];
  breached: number;
  upcoming: number;
  averageAgeHours: number | null;
}

export async function getGovernanceSLA(
  limit = 50,
): Promise<LoadResult<SLAResult>> {
  const authority = '/decisions';
  try {
    const page = await listDecisions({ limit, offset: 0 });

    // SLA thresholds derived from threat_level — due_at is not emitted by /decisions.
    const SLA_HOURS: Record<Severity, number | null> = {
      critical: 4, high: 24, medium: 72, low: 168, info: null,
    };

    const items: SLAItem[] = page.items.map((d: DecisionOut) => {
      const severity = normaliseSeverity(d.threat_level);
      const createdMs = d.created_at ? new Date(d.created_at).getTime() : null;
      const ageHours = createdMs
        ? Math.floor((Date.now() - createdMs) / 3_600_000)
        : null;
      const slaHours = SLA_HOURS[severity];
      const dueAt = (createdMs !== null && slaHours !== null)
        ? new Date(createdMs + slaHours * 3_600_000).toISOString()
        : null;
      const slaBreached = (ageHours !== null && slaHours !== null)
        ? ageHours > slaHours
        : false;

      return {
        id: d.id,
        title: d.event_type ?? 'Governance Event',
        severity,
        dueAt,
        createdAt: d.created_at ?? null,
        ageHours,
        slaBreached,
        owner: null,
      };
    });

    const breached = items.filter((i) => i.slaBreached).length;
    const upcoming = items.filter((i) => !i.slaBreached && i.dueAt !== null).length;
    const ages = items.map((i) => i.ageHours).filter((h): h is number => h !== null);
    const averageAgeHours = ages.length > 0 ? ages.reduce((a, b) => a + b, 0) / ages.length : null;

    return {
      ok: true,
      data: { items, breached, upcoming, averageAgeHours },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 8. Automation Safety Center ─────────────────────────────────────────────

export interface AutomationSafetyState {
  simulationRequired: boolean;
  rollbackAvailable: boolean;
  humanApprovalRequired: boolean;
  riskScore: number;
  blastRadius: string;
  killSwitchActive: boolean;
  executionConfidence: number;
  chainIntegrity: string;
  agentCount: number;
  quarantineCount: number;
}

export async function getAutomationSafety(): Promise<LoadResult<AutomationSafetyState>> {
  const authority = '/control-tower/snapshot';
  try {
    const result = await getControlTowerSnapshot();
    const s = result.data;

    const chainOk = s.chain_integrity.status === 'ok';
    const hasQuarantined = s.agents.quarantine_count > 0;
    const riskScore = deriveRiskScore(s);

    return {
      ok: true,
      data: {
        simulationRequired: riskScore >= 70,
        rollbackAvailable: chainOk,
        humanApprovalRequired: riskScore >= 85 || hasQuarantined,
        riskScore,
        blastRadius: deriveBlastRadius(s),
        killSwitchActive: s.agents.quarantine_count > 0,
        executionConfidence: chainOk ? Math.round(100 - riskScore * 0.3) : 0,
        chainIntegrity: s.chain_integrity.status,
        agentCount: s.agents.total,
        quarantineCount: s.agents.quarantine_count,
      },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 9. Cross Authority Timeline ─────────────────────────────────────────────

export interface TimelineEvent {
  id: string;
  ts: string;
  authority: string;
  category: string;
  eventType: string;
  severity: string;
  summary: string | null;
  requestId: string | null;
  immutable: boolean;
  auditable: boolean;
}

export interface CrossAuthorityTimelineResult {
  events: TimelineEvent[];
  authorities: string[];
  total: number;
}

export async function getCrossAuthorityTimeline(
  limit = 60,
): Promise<LoadResult<CrossAuthorityTimelineResult>> {
  const authority = '/ui/forensics/events + /feed/live';
  try {
    const [forensics, feed] = await Promise.all([
      getForensicsEvents({ limit }),
      getFeedLive(10),
    ]);

    const forensicEvents: TimelineEvent[] = forensics.events.map((e: ForensicsEvent) => ({
      id: `forensics-${e.event_id}`,
      ts: e.created_at ?? '',
      authority: 'Forensics Chain',
      category: e.event_category ?? 'platform',
      eventType: e.event_type,
      severity: e.severity ?? 'info',
      summary: e.reason ?? null,
      requestId: e.request_id ?? null,
      immutable: true,
      auditable: true,
    }));

    const feedItems = Array.isArray(feed.items) ? feed.items : [];
    const feedEvents: TimelineEvent[] = feedItems.map(
      (f: Record<string, unknown>, i: number) => ({
        id: `feed-${String(f.id ?? i)}`,
        ts: String(f.timestamp ?? f.created_at ?? ''),
        authority: 'Event Feed',
        category: String(f.event_type ?? 'platform'),
        eventType: String(f.event_type ?? 'feed_event'),
        severity: String(f.threat_level ?? f.severity ?? 'info'),
        summary: f.summary ? String(f.summary) : null,
        requestId: null,
        immutable: true,
        auditable: true,
      }),
    );

    const allEvents = [...forensicEvents, ...feedEvents].sort(
      (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime(),
    ).slice(0, limit);

    const authorities = Array.from(new Set(allEvents.map((e) => e.authority)));

    return {
      ok: true,
      data: { events: allEvents, authorities, total: allEvents.length },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── 10. Executive Operational Briefing ──────────────────────────────────────

export interface BriefingLine {
  category: 'changed' | 'risk_increased' | 'risk_reduced' | 'evidence_added'
    | 'evidence_missing' | 'policy_triggered' | 'automation_executed'
    | 'approval_required' | 'business_impact' | 'confidence' | 'unknown';
  label: string;
  value: string;
  authority: string;
}

export interface OperationalBriefingResult {
  lines: BriefingLine[];
  sufficientEvidence: boolean;
  insufficiencyReason: string | null;
  generatedAt: string;
  authorityCount: number;
}

export async function getOperationalBriefing(): Promise<LoadResult<OperationalBriefingResult>> {
  const authority = 'composite: /decisions + /governance/graph/stats + /ui/forensics/events';
  try {
    const [decisionsPage, graphStats, forensics] = await Promise.all([
      listDecisions({ limit: 10, offset: 0 }),
      getGraphStats(),
      getForensicsEvents({ limit: 10 }),
    ]);

    const recentDecisions = decisionsPage.items;
    const recentEvents = forensics.events;

    const lines: BriefingLine[] = [];

    // Changed
    if (recentDecisions.length > 0) {
      lines.push({
        category: 'changed',
        label: 'Recent governance decisions',
        value: `${recentDecisions.length} decisions in current window`,
        authority: '/decisions',
      });
    }

    // Risk signals
    const criticalDecisions = recentDecisions.filter(
      (d: DecisionOut) => d.threat_level === 'critical' || d.severity === 'critical',
    );
    if (criticalDecisions.length > 0) {
      lines.push({
        category: 'risk_increased',
        label: 'Critical severity events',
        value: `${criticalDecisions.length} critical decisions detected`,
        authority: '/decisions',
      });
    }

    // Evidence
    if (graphStats.node_count > 0) {
      lines.push({
        category: 'evidence_added',
        label: 'Governance graph nodes',
        value: `${graphStats.node_count} nodes, ${graphStats.edge_count} edges`,
        authority: '/governance/graph/stats',
      });
    }

    // Anomalies → missing evidence signal
    if (graphStats.anomaly_count > 0) {
      lines.push({
        category: 'evidence_missing',
        label: 'Governance anomalies active',
        value: `${graphStats.anomaly_count} anomalies detected`,
        authority: '/governance/graph/stats',
      });
    }

    // Approval required — use high-threat unreviewed decisions as a proxy
    // (workflow_state is not emitted by /decisions; explain_summary presence
    //  signals the decision has been reviewed/explained)
    const needsReview = recentDecisions.filter(
      (d: DecisionOut) =>
        (d.threat_level === 'critical' || d.threat_level === 'high') &&
        !d.explain_summary,
    );
    if (needsReview.length > 0) {
      lines.push({
        category: 'approval_required',
        label: 'High-severity decisions without explanation',
        value: `${needsReview.length} items may require review`,
        authority: '/decisions',
      });
    }

    // Forensics events
    if (recentEvents.length > 0) {
      const failures = recentEvents.filter((e: ForensicsEvent) => !e.success);
      if (failures.length > 0) {
        lines.push({
          category: 'risk_increased',
          label: 'Recent forensic failures',
          value: `${failures.length} events with failure status`,
          authority: '/ui/forensics/events',
        });
      }
    }

    const sufficientEvidence = lines.length >= 3 && graphStats.node_count > 0;
    const insufficiencyReason = sufficientEvidence
      ? null
      : 'Insufficient authoritative evidence — governance graph may not be populated.';

    return {
      ok: true,
      data: {
        lines,
        sufficientEvidence,
        insufficiencyReason,
        generatedAt: new Date().toISOString(),
        authorityCount: new Set(lines.map((l) => l.authority)).size,
      },
      authority,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error', authority };
  }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function normaliseSeverity(raw: unknown): Severity {
  switch (String(raw ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

function deriveAutomationStatus(e: ForensicsEvent): AutomationStatus {
  const t = e.event_type?.toLowerCase() ?? '';
  if (t.includes('blocked') || (!e.success && e.severity === 'critical')) return 'blocked';
  if (t.includes('failed') || (!e.success && e.severity !== 'critical')) return 'failed';
  if (t.includes('pending')) return 'pending';
  if (t.includes('scheduled')) return 'scheduled';
  if (t.includes('approval')) return 'approval_required';
  if (t.includes('running')) return 'running';
  if (e.success) return 'completed';
  return 'failed';
}

function derivePipelineStage(d: DecisionOut): PipelineStage {
  // DecisionOut does not carry workflow_state. Derive stage from fields
  // that are actually present: explain_summary, rules_triggered, pq_fallback,
  // and threat_level — in priority order from most-complete to least-complete.
  if (d.explain_summary) return 'verified';
  const rules = d.rules_triggered;
  const hasRules = Array.isArray(rules) ? rules.length > 0
    : rules !== null && rules !== undefined && String(rules) !== '[]' && String(rules) !== '{}';
  if (hasRules) return 'executed';
  if (d.pq_fallback) return 'simulation_completed';
  const tl = String(d.threat_level ?? '').toLowerCase();
  if (tl === 'critical' || tl === 'high') return 'policy_matched';
  if (tl === 'medium') return 'evaluated';
  return 'detected';
}

function deriveEvidenceStatus(
  trustScore: number,
  ageHours: number | null,
): EvidenceStatus {
  if (trustScore < 0.1) return 'missing';
  if (trustScore < 0.4) return 'unverified';
  if (ageHours !== null && ageHours > 168) return 'stale';
  if (ageHours !== null && ageHours > 120) return 'expiring';
  return 'current';
}

function mapAnomalyToConflictType(patternId: string): ConflictType {
  const p = patternId.toLowerCase();
  if (p.includes('duplicate')) return 'duplicate_policy';
  if (p.includes('conflict')) return 'conflicting_policy';
  if (p.includes('overlap') || p.includes('authority')) return 'overlapping_authority';
  if (p.includes('owner')) return 'missing_ownership';
  if (p.includes('orphan')) return 'orphaned_control';
  if (p.includes('dead') || p.includes('inactive')) return 'dead_policy';
  return 'contradicting_requirements';
}

function deriveRiskScore(s: import('./coreApi').ControlTowerSnapshotV1): number {
  let score = 0;
  if (s.chain_integrity.status !== 'ok') score += 40;
  if (s.agents.quarantine_count > 0) score += 20;
  if (s.connectors.errors && s.connectors.errors.length > 0) score += 15;
  if (s.lockers.status !== 'ok') score += 15;
  return Math.min(score, 100);
}

function deriveBlastRadius(s: import('./coreApi').ControlTowerSnapshotV1): string {
  if (s.agents.total === 0) return 'none';
  if (s.agents.quarantine_count >= s.agents.total) return 'full';
  if (s.agents.quarantine_count > 0) return 'partial';
  return 'contained';
}
