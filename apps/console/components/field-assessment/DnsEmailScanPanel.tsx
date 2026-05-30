'use client';

import { useEffect, useRef, useState } from 'react';
import { Button, Label } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type MsgraphRunStatus, type MsgraphRunStatusResult } from '@/lib/fieldAssessmentApi';

const STATUS_LABELS: Record<MsgraphRunStatus, string> = {
  pending_auth: 'Queued…',
  authenticating: 'Queued…',
  scanning: 'Checking DNS records…',
  importing: 'Importing findings…',
  complete: 'Scan complete',
  failed: 'Scan failed',
};

const TERMINAL_STATUSES: MsgraphRunStatus[] = ['complete', 'failed'];
const POLL_INTERVAL_MS = 3000;

interface Props {
  engagementId: string;
  onSuccess: (scanResultId: string) => void;
}

export function DnsEmailScanPanel({ engagementId, onSuccess }: Props) {
  const [domains, setDomains] = useState('');
  const [initiating, setInitiating] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);

  const [runId, setRunId] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState<MsgraphRunStatusResult | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const successFiredRef = useRef(false);

  useEffect(() => {
    if (!runId || !runStatus) return;
    if (TERMINAL_STATUSES.includes(runStatus.status)) {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      if (runStatus.status === 'complete' && runStatus.scan_result_id && !successFiredRef.current) {
        successFiredRef.current = true;
        onSuccess(runStatus.scan_result_id);
      }
    }
  }, [runId, runStatus, onSuccess]);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  function startPolling(id: string) {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const status = await fieldAssessmentApi.getMsgraphRunStatus(engagementId, id);
        setRunStatus(status);
      } catch { /* keep polling */ }
    }, POLL_INTERVAL_MS);
  }

  async function handleInitiate(e: React.FormEvent) {
    e.preventDefault();
    const domainList = domains.split('\n').map((d) => d.trim()).filter(Boolean);
    if (!domainList.length) return;
    setInitiating(true);
    setInitError(null);
    successFiredRef.current = false;
    try {
      const initiated = await fieldAssessmentApi.initiateDnsEmailScan(engagementId, { domains: domainList });
      setRunId(initiated.run_id);
      setRunStatus({ run_id: initiated.run_id, status: 'scanning', user_code: null, verification_uri: null, error: null, scan_result_id: null });
      startPolling(initiated.run_id);
    } catch (err) {
      setInitError(err instanceof Error ? err.message : 'Failed to initiate scan');
    } finally {
      setInitiating(false);
    }
  }

  function handleReset() {
    if (pollRef.current) clearInterval(pollRef.current);
    setRunId(null); setRunStatus(null); setInitError(null);
    successFiredRef.current = false;
  }

  const isComplete = runStatus?.status === 'complete';
  const isFailed = runStatus?.status === 'failed';

  return (
    <div className="space-y-4" aria-label="dns-email-scan-panel">
      <p className="text-xs text-muted">
        Checks DMARC, SPF, DKIM, MX, and DNSSEC for each domain. One domain per line (max 50).
      </p>
      {!runId && (
        <form onSubmit={handleInitiate} className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="dns-email-domains">Domains *</Label>
            <textarea
              id="dns-email-domains"
              required
              rows={4}
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder={'example.com\nacmecorp.io\nmycompany.org'}
              className="flex w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground font-mono placeholder:font-sans placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary resize-y"
              disabled={initiating}
            />
            <p className="text-[11px] text-muted">
              Checks: SPF record + policy, DMARC policy + reporting, DKIM selectors, MX records, DNSSEC.
            </p>
          </div>
          {initError && <Alert variant="destructive"><AlertDescription>{initError}</AlertDescription></Alert>}
          <Button
            type="submit"
            disabled={initiating || !domains.trim()}
            className="w-full sm:w-auto"
          >
            {initiating ? 'Initiating…' : 'Run DNS & Email Scan'}
          </Button>
        </form>
      )}
      {runId && runStatus && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${isComplete ? 'bg-success' : isFailed ? 'bg-danger' : 'bg-warning animate-pulse'}`} />
            <span className="text-sm text-foreground">{STATUS_LABELS[runStatus.status]}</span>
          </div>
          {isComplete && runStatus.scan_result_id && (
            <Alert variant="success">
              <AlertDescription>Scan imported — result ID: <code className="font-mono text-xs">{runStatus.scan_result_id}</code></AlertDescription>
            </Alert>
          )}
          {isFailed && (
            <Alert variant="destructive">
              <AlertDescription>{runStatus.error ?? 'Scan failed — check server logs for details.'}</AlertDescription>
            </Alert>
          )}
          {(isComplete || isFailed) && (
            <Button type="button" variant="outline" onClick={handleReset} className="text-xs h-8 px-3">
              Run another scan
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
