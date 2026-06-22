'use client';

import { useState } from 'react';
import { Button } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi } from '@/lib/fieldAssessmentApi';

type SensitivityLevel = 'critical' | 'high' | 'moderate' | 'low' | 'unknown';
type ReadinessLevel = 'governed' | 'partially_governed' | 'ungoverned' | 'unknown';

const SENSITIVITY_COLORS: Record<SensitivityLevel, string> = {
  critical: 'rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs text-red-300',
  high: 'rounded border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-xs text-orange-300',
  moderate: 'rounded border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-300',
  low: 'rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-xs text-blue-300',
  unknown: 'rounded border border-border bg-surface-2 px-2 py-0.5 text-xs text-muted',
};

const READINESS_LABELS: Record<ReadinessLevel, string> = {
  governed: 'Governed',
  partially_governed: 'Partial',
  ungoverned: 'Ungoverned',
  unknown: 'Unknown',
};

interface Props {
  engagementId: string;
  onSuccess: (scanResultId: string) => void;
}

type MappingResult = {
  scan_result_id: string;
  tools_mapped: number;
  findings_imported: number;
  status: string;
  summary: Record<string, unknown>;
};

export function AiDataAccessMappingPanel({ engagementId, onSuccess }: Props) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MappingResult | null>(null);

  async function handleRun() {
    setRunning(true);
    setError(null);
    try {
      const res = await fieldAssessmentApi.runAiDataAccessMapping(engagementId, {});
      setResult(res);
      onSuccess(res.scan_result_id);
    } catch (e: unknown) {
      const msg =
        e instanceof Error
          ? e.message
          : 'Mapping failed. Ensure AI Tool Discovery scan has been completed first.';
      setError(msg);
    } finally {
      setRunning(false);
    }
  }

  const sensitivityDist = result?.summary?.sensitivity_distribution as
    | Record<SensitivityLevel, number>
    | undefined;
  const readinessDist = result?.summary?.governance_readiness_distribution as
    | Record<ReadinessLevel, number>
    | undefined;
  const ownerDist = result?.summary?.owner_distribution as
    | Record<string, number>
    | undefined;
  const scopeDist = result?.summary?.scope_distribution as
    | Record<string, number>
    | undefined;
  const categories = result?.summary?.data_categories_observed as string[] | undefined;

  return (
    <div className="space-y-4" aria-label="ai-data-access-mapping-panel">
      <div className="space-y-2">
        <p className="text-xs text-muted">
          Maps AI tool permissions to business data categories, sensitivity levels,
          exposure scope, data ownership, and governance readiness. Deterministic — no AI
          scoring. Requires a completed AI Tool Discovery scan. No additional Graph API
          calls are made.
        </p>
        <Button size="sm" onClick={handleRun} disabled={running} aria-busy={running}>
          {running ? 'Mapping…' : 'Run AI Data Access Mapping'}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {result && (
        <div className="space-y-3">
          <Alert>
            <AlertDescription>
              Mapping complete —{' '}
              <strong>{result.tools_mapped}</strong> tool(s) mapped,{' '}
              <strong>{result.findings_imported}</strong> finding(s) imported.
              Result ID:{' '}
              <code className="font-mono text-xs">{result.scan_result_id}</code>
            </AlertDescription>
          </Alert>

          {sensitivityDist && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted">Data Sensitivity</p>
              <div className="flex flex-wrap gap-1.5">
                {(
                  ['critical', 'high', 'moderate', 'low', 'unknown'] as SensitivityLevel[]
                ).map((level) =>
                  (sensitivityDist[level] ?? 0) > 0 ? (
                    <span key={level} className={SENSITIVITY_COLORS[level]}>
                      {level.charAt(0).toUpperCase() + level.slice(1)}:{' '}
                      {sensitivityDist[level]}
                    </span>
                  ) : null,
                )}
              </div>
            </div>
          )}

          {readinessDist && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted">Governance Readiness</p>
              <div className="flex flex-wrap gap-1.5">
                {(
                  [
                    'governed',
                    'partially_governed',
                    'ungoverned',
                    'unknown',
                  ] as ReadinessLevel[]
                ).map((level) =>
                  (readinessDist[level] ?? 0) > 0 ? (
                    <span
                      key={level}
                      className="rounded border border-border bg-surface-2 px-2 py-0.5 text-xs text-foreground"
                    >
                      {READINESS_LABELS[level]}: {readinessDist[level]}
                    </span>
                  ) : null,
                )}
              </div>
            </div>
          )}

          {scopeDist && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted">Exposure Scope</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(scopeDist)
                  .filter(([, v]) => v > 0)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([scope, count]) => (
                    <span
                      key={scope}
                      className="rounded border border-border bg-surface-2 px-2 py-0.5 text-xs text-foreground"
                    >
                      {scope}: {count}
                    </span>
                  ))}
              </div>
            </div>
          )}

          {ownerDist && Object.keys(ownerDist).length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted">Data Ownership</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(ownerDist)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([owner, count]) => (
                    <span
                      key={owner}
                      className="rounded border border-border bg-surface-2 px-2 py-0.5 text-xs text-foreground"
                    >
                      {owner}: {count}
                    </span>
                  ))}
              </div>
            </div>
          )}

          {categories && categories.length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted">
                Data Categories Observed
              </p>
              <div className="flex flex-wrap gap-1.5">
                {categories.map((cat) => (
                  <span
                    key={cat}
                    className="rounded border border-border bg-surface-2 px-2 py-0.5 text-xs text-foreground"
                  >
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
