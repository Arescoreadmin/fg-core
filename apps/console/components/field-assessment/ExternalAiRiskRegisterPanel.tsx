'use client';

import { useState } from 'react';
import { Button } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi } from '@/lib/fieldAssessmentApi';

type RiskScore = 'critical' | 'high' | 'moderate' | 'low';
type RiskCategory =
  | 'tenant_wide_permissions'
  | 'sensitive_data_access'
  | 'unverified_publisher'
  | 'overprivileged_oauth'
  | 'shadow_ai'
  | 'unknown_owner'
  | 'no_dpa_baa_vendor_review'
  | 'no_approval_record';

const SCORE_BADGE: Record<RiskScore, string> = {
  critical:
    'rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-300',
  high: 'rounded border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-xs font-medium text-orange-300',
  moderate:
    'rounded border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 text-xs font-medium text-yellow-200',
  low: 'rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-xs font-medium text-blue-300',
};

const GOV_STATE_BADGE: Record<string, string> = {
  ungoverned:
    'rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[11px] text-red-300',
  partially_governed:
    'rounded border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 text-[11px] text-yellow-200',
  governed:
    'rounded border border-green-500/30 bg-green-500/10 px-1.5 py-0.5 text-[11px] text-green-300',
  exception_granted:
    'rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 text-[11px] text-purple-300',
  unknown: 'rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted',
};

const CATEGORY_LABELS: Record<RiskCategory, string> = {
  tenant_wide_permissions: 'Tenant-Wide',
  sensitive_data_access: 'Sensitive Data',
  unverified_publisher: 'Unverified Publisher',
  overprivileged_oauth: 'Over-Privileged OAuth',
  shadow_ai: 'Shadow AI',
  unknown_owner: 'Unknown Owner',
  no_dpa_baa_vendor_review: 'No Vendor Review',
  no_approval_record: 'No Approval Record',
};

type RiskRecord = {
  risk_id: string;
  tool_name: string;
  vendor: string;
  risk_score: RiskScore;
  risk_category: string;
  risk_categories: string[];
  risk_reason: string;
  recommended_action: string;
  review_status: string;
  business_owner: string;
  technical_owner: string;
  risk_owner: string | null;
  owner_type: string;
  publisher_trust: string;
  admin_consent: boolean;
  sensitive_data_exposure: string[];
  governance_state: string;
  regulatory_flags: string[];
  vendor_review_status: string;
  vendor_dpa_status: string;
  vendor_baa_status: string;
  risk_age_days: number | null;
  first_detected_at: string | null;
  last_reviewed_at: string | null;
  remediation_status: string;
  remediation_target_date: string | null;
  decision_refs: string[];
  risk_acceptance_refs: string[];
  exception_refs: string[];
  approval_refs: string[];
  evidence_refs: string[];
  finding_refs: string[];
};

type Summary = {
  total_risks?: number;
  score_distribution?: Record<RiskScore, number>;
  ownership_gaps?: number;
  governance_gaps?: number;
  shadow_ai_count?: number;
  unverified_publisher_count?: number;
  tenant_wide_count?: number;
  governance_distribution?: Record<string, number>;
  vendor_distribution?: Record<string, number>;
  remediation_distribution?: Record<string, number>;
  regulatory_distribution?: Record<string, number>;
  risks_without_review?: number;
  risks_without_vendor_approval?: number;
  stale_risks?: number;
};

type RunResult = {
  scan_result_id: string;
  risks_imported: number;
  findings_imported: number;
  status: string;
  summary: Summary;
};

interface Props {
  engagementId: string;
  onSuccess: (scanResultId: string) => void;
}

export function ExternalAiRiskRegisterPanel({ engagementId, onSuccess }: Props) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RunResult | null>(null);
  const [records, setRecords] = useState<RiskRecord[] | null>(null);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [filterScore, setFilterScore] = useState<string>('');
  const [filterCategory, setFilterCategory] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterGovState, setFilterGovState] = useState<string>('');

  async function handleRun() {
    setRunning(true);
    setError(null);
    try {
      const res = await fieldAssessmentApi.runExternalAiRiskRegister(engagementId, {});
      setResult(res);
      onSuccess(res.scan_result_id);
      await fetchRecords();
    } catch (e: unknown) {
      const msg =
        e instanceof Error
          ? e.message
          : 'Risk register generation failed. Ensure AI Tool Discovery scan has been completed first.';
      setError(msg);
    } finally {
      setRunning(false);
    }
  }

  async function fetchRecords() {
    setLoadingRecords(true);
    try {
      const data = await fieldAssessmentApi.listExternalAiRiskRecords(
        engagementId,
        filterScore || undefined,
        filterCategory || undefined,
        filterStatus || undefined,
      );
      setRecords(data.items);
    } catch {
      // silently ignore list errors after run
    } finally {
      setLoadingRecords(false);
    }
  }

  const scoreDist = result?.summary?.score_distribution;
  const govDist = result?.summary?.governance_distribution;

  const filteredRecords = records
    ? records.filter((r) => {
        if (filterScore && r.risk_score !== filterScore) return false;
        if (filterCategory && !r.risk_categories.includes(filterCategory)) return false;
        if (filterStatus && r.review_status !== filterStatus) return false;
        if (filterGovState && r.governance_state !== filterGovState) return false;
        return true;
      })
    : null;

  return (
    <div className="space-y-4" aria-label="external-ai-risk-register-panel">
      <div className="space-y-2">
        <p className="text-xs text-muted">
          Generates a deterministic AI risk register from AI Tool Discovery (PR 1) and
          AI Data Access Mapping (PR 2) evidence. No new Graph API calls. Every risk
          traces to evidence and uses rules-based scoring — no AI-generated risk values.
        </p>
        <div className="flex gap-2">
          <Button size="sm" onClick={handleRun} disabled={running} aria-busy={running}>
            {running ? 'Generating…' : 'Generate AI Risk Register'}
          </Button>
          {records !== null && (
            <Button size="sm" variant="outline" onClick={fetchRecords} disabled={loadingRecords}>
              {loadingRecords ? 'Refreshing…' : 'Refresh'}
            </Button>
          )}
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {result && (
        <Alert>
          <AlertDescription>
            Risk register generated —{' '}
            <strong>{result.risks_imported}</strong> risk record(s),{' '}
            <strong>{result.findings_imported}</strong> finding(s) imported.
            {scoreDist && (
              <span className="ml-2">
                {scoreDist.critical > 0 && (
                  <span className="mr-1 text-red-300">{scoreDist.critical} critical</span>
                )}
                {scoreDist.high > 0 && (
                  <span className="mr-1 text-orange-300">{scoreDist.high} high</span>
                )}
                {scoreDist.moderate > 0 && (
                  <span className="mr-1 text-yellow-200">{scoreDist.moderate} moderate</span>
                )}
                {scoreDist.low > 0 && (
                  <span className="mr-1 text-blue-300">{scoreDist.low} low</span>
                )}
              </span>
            )}
          </AlertDescription>
        </Alert>
      )}

      {/* Executive dashboard metrics */}
      {result && (
        <div className="space-y-2">
          {/* Risk + governance alerts */}
          <div className="flex flex-wrap gap-2 text-xs">
            {(result.summary?.ownership_gaps ?? 0) > 0 && (
              <span className="rounded border border-amber-500/30 bg-amber-500/5 px-2 py-0.5 text-amber-200">
                {result.summary.ownership_gaps} without owner
              </span>
            )}
            {(result.summary?.governance_gaps ?? 0) > 0 && (
              <span className="rounded border border-amber-500/30 bg-amber-500/5 px-2 py-0.5 text-amber-200">
                {result.summary.governance_gaps} no approval record
              </span>
            )}
            {(result.summary?.shadow_ai_count ?? 0) > 0 && (
              <span className="rounded border border-border bg-surface-2 px-2 py-0.5 text-foreground">
                {result.summary.shadow_ai_count} shadow AI
              </span>
            )}
            {(result.summary?.tenant_wide_count ?? 0) > 0 && (
              <span className="rounded border border-red-500/30 bg-red-500/5 px-2 py-0.5 text-red-300">
                {result.summary.tenant_wide_count} tenant-wide
              </span>
            )}
            {(result.summary?.risks_without_review ?? 0) > 0 && (
              <span className="rounded border border-amber-500/30 bg-amber-500/5 px-2 py-0.5 text-amber-200">
                {result.summary.risks_without_review} unreviewed
              </span>
            )}
            {(result.summary?.risks_without_vendor_approval ?? 0) > 0 && (
              <span className="rounded border border-amber-500/30 bg-amber-500/5 px-2 py-0.5 text-amber-200">
                {result.summary.risks_without_vendor_approval} vendor not approved
              </span>
            )}
            {(result.summary?.stale_risks ?? 0) > 0 && (
              <span className="rounded border border-red-500/30 bg-red-500/5 px-2 py-0.5 text-red-300">
                {result.summary.stale_risks} stale (&gt;90 days)
              </span>
            )}
          </div>

          {/* Governance distribution */}
          {govDist && (
            <div className="flex flex-wrap gap-1.5 text-xs">
              <span className="text-muted mr-1 self-center">Governance:</span>
              {govDist.ungoverned > 0 && (
                <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-red-300">
                  {govDist.ungoverned} ungoverned
                </span>
              )}
              {govDist.partially_governed > 0 && (
                <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 text-yellow-200">
                  {govDist.partially_governed} partial
                </span>
              )}
              {govDist.governed > 0 && (
                <span className="rounded border border-green-500/30 bg-green-500/10 px-2 py-0.5 text-green-300">
                  {govDist.governed} governed
                </span>
              )}
              {(govDist.exception_granted ?? 0) > 0 && (
                <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-purple-300">
                  {govDist.exception_granted} exception
                </span>
              )}
            </div>
          )}

          {/* Regulatory distribution */}
          {result.summary?.regulatory_distribution &&
            Object.keys(result.summary.regulatory_distribution).length > 0 && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                <span className="text-muted mr-1 self-center">Regulatory:</span>
                {Object.entries(result.summary.regulatory_distribution).map(([flag, count]) => (
                  <span
                    key={flag}
                    className="rounded border border-border bg-surface-2 px-2 py-0.5 text-muted"
                  >
                    {flag} ({count})
                  </span>
                ))}
              </div>
            )}
        </div>
      )}

      {/* Filters */}
      {records !== null && (
        <div className="flex flex-wrap gap-2">
          <select
            className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground"
            value={filterScore}
            onChange={(e) => setFilterScore(e.target.value)}
            aria-label="Filter by risk score"
          >
            <option value="">All scores</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="moderate">Moderate</option>
            <option value="low">Low</option>
          </select>
          <select
            className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground"
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            aria-label="Filter by risk category"
          >
            <option value="">All categories</option>
            {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
          <select
            className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            aria-label="Filter by review status"
          >
            <option value="">All statuses</option>
            <option value="unreviewed">Unreviewed</option>
            <option value="under_review">Under Review</option>
            <option value="accepted">Accepted</option>
            <option value="mitigated">Mitigated</option>
            <option value="risk_accepted">Risk Accepted</option>
            <option value="closed">Closed</option>
          </select>
          <select
            className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground"
            value={filterGovState}
            onChange={(e) => setFilterGovState(e.target.value)}
            aria-label="Filter by governance state"
          >
            <option value="">All governance</option>
            <option value="ungoverned">Ungoverned</option>
            <option value="partially_governed">Partially Governed</option>
            <option value="governed">Governed</option>
            <option value="exception_granted">Exception Granted</option>
          </select>
        </div>
      )}

      {/* Risk record list */}
      {filteredRecords !== null && (
        <div className="space-y-2">
          {filteredRecords.length === 0 ? (
            <p className="text-xs text-muted">No risk records match the current filters.</p>
          ) : (
            filteredRecords.map((rec) => <RiskRecordCard key={rec.risk_id} record={rec} />)
          )}
        </div>
      )}
    </div>
  );
}

function RiskRecordCard({ record }: { record: RiskRecord }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded border border-border bg-surface-2 p-3">
      <div
        className="flex cursor-pointer flex-wrap items-center gap-2"
        onClick={() => setExpanded((x) => !x)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && setExpanded((x) => !x)}
        aria-expanded={expanded}
      >
        <span className="text-sm font-medium text-foreground">{record.tool_name}</span>
        <span className="text-xs text-muted">{record.vendor}</span>
        <span className={SCORE_BADGE[record.risk_score] ?? SCORE_BADGE.low}>
          {record.risk_score.toUpperCase()}
        </span>
        <span
          className={
            GOV_STATE_BADGE[record.governance_state] ?? GOV_STATE_BADGE.unknown
          }
        >
          {record.governance_state.replace(/_/g, ' ')}
        </span>
        <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted">
          {record.review_status.replace(/_/g, ' ')}
        </span>
        {record.remediation_status !== 'not_started' && (
          <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted">
            remediation: {record.remediation_status.replace(/_/g, ' ')}
          </span>
        )}
        {record.publisher_trust === 'unverified' && (
          <span className="rounded border border-amber-500/30 bg-amber-500/5 px-1.5 py-0.5 text-[11px] text-amber-200">
            unverified publisher
          </span>
        )}
        {record.admin_consent && (
          <span className="rounded border border-red-500/30 bg-red-500/5 px-1.5 py-0.5 text-[11px] text-red-300">
            admin consent
          </span>
        )}
        {record.risk_age_days !== null && record.risk_age_days > 90 && (
          <span className="rounded border border-red-500/30 bg-red-500/5 px-1.5 py-0.5 text-[11px] text-red-300">
            {record.risk_age_days}d old
          </span>
        )}
      </div>

      {expanded && (
        <div className="mt-3 space-y-2 text-xs">
          {/* Risk categories */}
          <div className="flex flex-wrap gap-1.5">
            {record.risk_categories.map((cat) => (
              <span
                key={cat}
                className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted"
              >
                {(CATEGORY_LABELS as Record<string, string>)[cat] ?? cat}
              </span>
            ))}
          </div>

          {/* Regulatory flags */}
          {record.regulatory_flags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              <span className="text-muted self-center">Regulatory:</span>
              {record.regulatory_flags.map((flag) => (
                <span
                  key={flag}
                  className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted"
                >
                  {flag}
                </span>
              ))}
            </div>
          )}

          <p className="text-muted">
            <span className="font-medium text-foreground">Risk: </span>
            {record.risk_reason}
          </p>

          <p className="text-muted">
            <span className="font-medium text-foreground">Action: </span>
            {record.recommended_action}
          </p>

          {record.sensitive_data_exposure.length > 0 && (
            <div>
              <span className="font-medium text-foreground">Sensitive data: </span>
              <span className="text-muted">{record.sensitive_data_exposure.join(', ')}</span>
            </div>
          )}

          <dl className="grid gap-1.5 sm:grid-cols-3">
            <div>
              <dt className="text-muted">Business owner</dt>
              <dd className="text-foreground">{record.business_owner}</dd>
            </div>
            <div>
              <dt className="text-muted">Technical owner</dt>
              <dd className="text-foreground">{record.technical_owner}</dd>
            </div>
            <div>
              <dt className="text-muted">Risk owner</dt>
              <dd className="text-foreground">{record.risk_owner ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-muted">Owner type</dt>
              <dd className="text-foreground">{record.owner_type}</dd>
            </div>
            <div>
              <dt className="text-muted">Vendor review</dt>
              <dd className="text-foreground">
                {record.vendor_review_status.replace(/_/g, ' ')}
              </dd>
            </div>
            <div>
              <dt className="text-muted">DPA status</dt>
              <dd className="text-foreground">{record.vendor_dpa_status}</dd>
            </div>
            <div>
              <dt className="text-muted">BAA status</dt>
              <dd className="text-foreground">{record.vendor_baa_status}</dd>
            </div>
            {record.risk_age_days !== null && (
              <div>
                <dt className="text-muted">Risk age</dt>
                <dd className="text-foreground">{record.risk_age_days} day(s)</dd>
              </div>
            )}
            {record.last_reviewed_at && (
              <div>
                <dt className="text-muted">Last reviewed</dt>
                <dd className="text-foreground">
                  {new Date(record.last_reviewed_at).toLocaleDateString()}
                </dd>
              </div>
            )}
            {record.remediation_target_date && (
              <div>
                <dt className="text-muted">Remediation target</dt>
                <dd className="text-foreground">
                  {new Date(record.remediation_target_date).toLocaleDateString()}
                </dd>
              </div>
            )}
          </dl>

          {/* Decision refs */}
          {(record.decision_refs.length > 0 ||
            record.risk_acceptance_refs.length > 0 ||
            record.exception_refs.length > 0 ||
            record.approval_refs.length > 0) && (
            <div className="space-y-0.5">
              {record.decision_refs.length > 0 && (
                <div>
                  <span className="font-medium text-foreground">Decisions: </span>
                  <span className="font-mono text-muted">
                    {record.decision_refs.slice(0, 2).join(', ')}
                    {record.decision_refs.length > 2 &&
                      ` +${record.decision_refs.length - 2} more`}
                  </span>
                </div>
              )}
              {record.exception_refs.length > 0 && (
                <div>
                  <span className="font-medium text-foreground">Exceptions: </span>
                  <span className="font-mono text-muted">
                    {record.exception_refs.join(', ')}
                  </span>
                </div>
              )}
            </div>
          )}

          {record.evidence_refs.length > 0 && (
            <div>
              <span className="font-medium text-foreground">Evidence: </span>
              <span className="font-mono text-muted">
                {record.evidence_refs.slice(0, 3).join(', ')}
                {record.evidence_refs.length > 3 &&
                  ` +${record.evidence_refs.length - 3} more`}
              </span>
            </div>
          )}

          {record.finding_refs.length > 0 && (
            <div>
              <span className="font-medium text-foreground">Findings: </span>
              <span className="font-mono text-muted">
                {record.finding_refs.slice(0, 2).join(', ')}
                {record.finding_refs.length > 2 &&
                  ` +${record.finding_refs.length - 2} more`}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
