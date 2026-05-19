'use client';

import { useState } from 'react';
import { Button, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Textarea } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type ScanSourceType, type ScanResultSummary } from '@/lib/fieldAssessmentApi';

const SOURCE_TYPES: { value: ScanSourceType; label: string }[] = [
  { value: 'microsoft_graph', label: 'Microsoft Graph' },
  { value: 'google_workspace', label: 'Google Workspace' },
  { value: 'aws', label: 'AWS' },
  { value: 'azure', label: 'Azure' },
  { value: 'gcp', label: 'GCP' },
  { value: 'network_scan', label: 'Network Scan' },
  { value: 'endpoint_inventory', label: 'Endpoint Inventory' },
  { value: 'oauth_inventory', label: 'OAuth Inventory' },
];

interface ParsedPreview {
  keyCount: number;
  payloadSize: number;
  schemaVersion: string | null;
  topLevelKeys: string[];
}

function parsePreview(raw: string): { parsed: Record<string, unknown>; preview: ParsedPreview } | { error: string } {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { error: 'Payload must be a JSON object (not array or primitive)' };
    }
    const keys = Object.keys(parsed);
    return {
      parsed,
      preview: {
        keyCount: keys.length,
        payloadSize: new Blob([raw]).size,
        schemaVersion: typeof parsed.schema_version === 'string' ? parsed.schema_version : null,
        topLevelKeys: keys.slice(0, 8),
      },
    };
  } catch (e) {
    return { error: `Invalid JSON: ${e instanceof SyntaxError ? e.message : 'parse error'}` };
  }
}

interface Props {
  engagementId: string;
  onSuccess: (result: ScanResultSummary) => void;
}

export function ScanImportPanel({ engagementId, onSuccess }: Props) {
  const [sourceType, setSourceType] = useState<ScanSourceType | ''>('');
  const [jsonText, setJsonText] = useState('');
  const [collectedAt, setCollectedAt] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ScanResultSummary | null>(null);

  const parseResult = jsonText.trim() ? parsePreview(jsonText) : null;
  const preview = parseResult && 'preview' in parseResult ? parseResult.preview : null;
  const parseError = parseResult && 'error' in parseResult ? parseResult.error : null;

  const canSubmit =
    sourceType !== '' &&
    jsonText.trim() !== '' &&
    !parseError &&
    collectedAt !== '' &&
    !submitting;

  async function handleSubmit() {
    if (!canSubmit || !parseResult || !('parsed' in parseResult)) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const result = await fieldAssessmentApi.ingestScan(engagementId, {
        source_type: sourceType as ScanSourceType,
        collected_at: collectedAt,
        raw_payload: parseResult.parsed,
        schema_version: preview?.schemaVersion ?? '1.0',
        object_count: preview?.keyCount ?? 0,
      });
      setLastResult(result);
      setJsonText('');
      setSourceType('');
      setCollectedAt('');
      onSuccess(result);
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="scan-import-panel">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="scan-source-type">Source Type *</Label>
          <Select
            value={sourceType}
            onValueChange={(v) => setSourceType(v as ScanSourceType)}
          >
            <SelectTrigger id="scan-source-type" aria-required="true">
              <SelectValue placeholder="Select scan source…" />
            </SelectTrigger>
            <SelectContent>
              {SOURCE_TYPES.map((s) => (
                <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="scan-collected-at">Collected At (ISO 8601) *</Label>
          <input
            id="scan-collected-at"
            type="datetime-local"
            aria-required="true"
            className="flex h-10 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
            onChange={(e) => {
              const v = e.target.value;
              setCollectedAt(v ? new Date(v).toISOString() : '');
            }}
          />
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="scan-json-paste">Scan Result JSON *</Label>
        <Textarea
          id="scan-json-paste"
          aria-required="true"
          aria-describedby={parseError ? 'scan-json-error' : undefined}
          placeholder={'{\n  "source_type": "...",\n  "users": [],\n  "devices": []\n}'}
          className="min-h-[140px] font-mono text-xs"
          value={jsonText}
          onChange={(e) => {
            setJsonText(e.target.value);
            setLastResult(null);
          }}
        />
        {parseError && (
          <p id="scan-json-error" className="text-xs text-danger mt-1" role="alert">{parseError}</p>
        )}
      </div>

      {preview && (
        <div className="rounded border border-border bg-surface-2 p-3 space-y-2">
          <p className="text-xs font-semibold text-muted uppercase tracking-wider">Payload Preview</p>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            <dt className="text-muted">Top-level keys</dt>
            <dd className="text-foreground font-mono">{preview.keyCount}</dd>
            <dt className="text-muted">Payload size</dt>
            <dd className="text-foreground font-mono">{(preview.payloadSize / 1024).toFixed(1)} KB</dd>
            {preview.schemaVersion && (
              <>
                <dt className="text-muted">Schema version</dt>
                <dd className="text-foreground font-mono">{preview.schemaVersion}</dd>
              </>
            )}
            <dt className="text-muted">Keys detected</dt>
            <dd className="text-foreground font-mono break-all">{preview.topLevelKeys.join(', ')}{preview.keyCount > 8 ? '…' : ''}</dd>
          </dl>
        </div>
      )}

      {lastResult && (
        <Alert variant="success">
          <AlertDescription>
            Scan imported — evidence hash: <code className="font-mono text-xs">{lastResult.evidence_hash}</code>
          </AlertDescription>
        </Alert>
      )}

      {submitError && (
        <Alert variant="destructive">
          <AlertDescription>{submitError}</AlertDescription>
        </Alert>
      )}

      <Button
        onClick={handleSubmit}
        disabled={!canSubmit}
        className="w-full sm:w-auto"
        aria-label="Submit scan result"
      >
        {submitting ? 'Importing…' : 'Import Scan Result'}
      </Button>
    </div>
  );
}
