'use client';

import { useRef, useState } from 'react';
import { fieldAssessmentApi, type CaptureObservationPayload } from '@/lib/fieldAssessmentApi';

const COLUMNS = ['domain', 'observation_type', 'severity', 'title', 'description'] as const;

const TEMPLATE = `domain,observation_type,severity,title,description
ai_governance,finding,high,"Missing data governance policy","No formal policy for data classification or handling is documented."
access_management,gap,medium,"MFA not enforced","Multi-factor authentication is not required for privileged accounts."
`;

function parseCSV(text: string): { rows: Record<string, string>[]; error: string | null } {
  const lines = text.trim().split('\n').filter(Boolean);
  if (lines.length < 2) return { rows: [], error: 'CSV must have a header row and at least one data row.' };

  const header = parseCSVLine(lines[0]).map((h) => h.trim().toLowerCase());
  for (const col of COLUMNS) {
    if (!header.includes(col)) {
      return { rows: [], error: `Missing required column: "${col}". Required: ${COLUMNS.join(', ')}` };
    }
  }

  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const vals = parseCSVLine(lines[i]);
    const row: Record<string, string> = {};
    header.forEach((h, j) => { row[h] = (vals[j] ?? '').trim(); });
    rows.push(row);
  }
  return { rows, error: null };
}

function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else { inQuotes = !inQuotes; }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

interface Props {
  engagementId: string;
  onImported: () => void;
}

export function BulkObservationImport({ engagementId, onImported }: Props) {
  const [open, setOpen] = useState(false);
  const [csv, setCsv] = useState('');
  const [result, setResult] = useState<{ created: number; skipped: number; errors: string[] } | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setCsv((ev.target?.result as string) ?? '');
    reader.readAsText(file);
  }

  async function handleImport() {
    setParseError(null);
    setResult(null);
    const { rows, error } = parseCSV(csv);
    if (error) { setParseError(error); return; }
    if (rows.length === 0) { setParseError('No data rows found.'); return; }

    const payloads: CaptureObservationPayload[] = rows.map((r) => ({
      domain: r.domain as CaptureObservationPayload['domain'],
      observation_type: r.observation_type as CaptureObservationPayload['observation_type'],
      severity: r.severity as CaptureObservationPayload['severity'],
      title: r.title,
      description: r.description,
    }));

    setLoading(true);
    try {
      const res = await fieldAssessmentApi.bulkImportObservations(engagementId, payloads);
      setResult({ created: res.created, skipped: res.skipped, errors: res.errors });
      if (res.created > 0) { setCsv(''); onImported(); }
    } catch (err) {
      setParseError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-xs text-primary hover:underline focus:outline-none"
      >
        {open ? '▲ Hide bulk import' : '▼ Bulk import from CSV'}
      </button>

      {open && (
        <div className="mt-2 rounded border border-border bg-surface-1 p-3 space-y-3">
          <p className="text-xs text-muted">
            Paste CSV or upload a file. Required columns:{' '}
            <span className="font-mono">{COLUMNS.join(', ')}</span>
          </p>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setCsv(TEMPLATE)}
              className="text-xs text-primary hover:underline focus:outline-none"
            >
              Load template
            </button>
            <span className="text-muted text-xs">or</span>
            <label className="text-xs text-primary hover:underline cursor-pointer">
              Upload CSV
              <input ref={fileRef} type="file" accept=".csv,text/csv" className="sr-only" onChange={handleFile} />
            </label>
          </div>

          <textarea
            value={csv}
            onChange={(e) => setCsv(e.target.value)}
            rows={6}
            placeholder="domain,observation_type,severity,title,description&#10;ai_governance,finding,high,..."
            className="w-full rounded border border-border bg-surface-2 px-2 py-1.5 text-xs font-mono text-foreground placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary/40 resize-y"
          />

          {parseError && (
            <p className="text-xs text-red-300">{parseError}</p>
          )}

          {result && (
            <div className={`rounded border p-2 text-xs space-y-1 ${result.created > 0 ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-border bg-surface-2'}`}>
              <p className="font-medium text-foreground">
                {result.created} imported, {result.skipped} skipped
              </p>
              {result.errors.map((e, i) => (
                <p key={i} className="text-red-300 font-mono">{e}</p>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={handleImport}
            disabled={loading || !csv.trim()}
            className="rounded bg-primary px-3 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Importing…' : 'Import'}
          </button>
        </div>
      )}
    </div>
  );
}
