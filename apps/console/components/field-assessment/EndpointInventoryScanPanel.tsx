'use client';

import { useEffect, useRef, useState } from 'react';
import { Button, Label } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type MsgraphRunStatus, type MsgraphRunStatusResult } from '@/lib/fieldAssessmentApi';

const STATUS_LABELS: Record<MsgraphRunStatus, string> = {
  pending_auth: 'Waiting for authentication…',
  authenticating: 'Waiting for device authentication…',
  scanning: 'Running endpoint inventory scan…',
  importing: 'Importing scan results…',
  complete: 'Scan complete',
  failed: 'Scan failed',
  timeout: 'Scan timed out',
};

const TERMINAL_STATUSES: MsgraphRunStatus[] = ['complete', 'failed', 'timeout'];
const POLL_INTERVAL_MS = 3000;

interface Props {
  engagementId: string;
  onSuccess: (scanResultId: string) => void;
}

export function EndpointInventoryScanPanel({ engagementId, onSuccess }: Props) {
  const [azureTenantId, setAzureTenantId] = useState('');
  const [operatorName, setOperatorName] = useState('');
  const [operatorOrg, setOperatorOrg] = useState('');

  const [initiating, setInitiating] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);

  const [runId, setRunId] = useState<string | null>(null);
  const [userCode, setUserCode] = useState<string | null>(null);
  const [verificationUri, setVerificationUri] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState<MsgraphRunStatusResult | null>(null);
  const [copied, setCopied] = useState(false);

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
    if (!azureTenantId.trim()) return;
    setInitiating(true);
    setInitError(null);
    successFiredRef.current = false;
    try {
      const initiated = await fieldAssessmentApi.initiateEndpointInventoryScan(engagementId, {
        azure_tenant_id: azureTenantId.trim(),
        ...(operatorName.trim() ? { operator_name: operatorName.trim() } : {}),
        ...(operatorOrg.trim() ? { operator_org: operatorOrg.trim() } : {}),
      });
      setRunId(initiated.run_id);
      setUserCode(initiated.user_code);
      setVerificationUri(initiated.verification_uri);
      setRunStatus({ run_id: initiated.run_id, status: 'pending_auth', user_code: initiated.user_code, verification_uri: initiated.verification_uri, error: null, scan_result_id: null });
      startPolling(initiated.run_id);
    } catch (err) {
      setInitError(err instanceof Error ? err.message : 'Failed to initiate scan');
    } finally {
      setInitiating(false);
    }
  }

  function handleReset() {
    if (pollRef.current) clearInterval(pollRef.current);
    setRunId(null); setUserCode(null); setVerificationUri(null);
    setRunStatus(null); setInitError(null); setCopied(false);
    successFiredRef.current = false;
  }

  async function handleCopy() {
    if (!userCode) return;
    try { await navigator.clipboard.writeText(userCode); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* no-op */ }
  }

  const isComplete = runStatus?.status === 'complete';
  const isFailed = runStatus?.status === 'failed';

  return (
    <div className="space-y-4" aria-label="endpoint-inventory-scan-panel">
      <p className="text-xs text-muted">
        Enumerates Azure AD registered devices and Intune managed devices via MS Graph.
      </p>
      {!runId && (
        <form onSubmit={handleInitiate} className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="endpoint-tenant-id">Azure Tenant ID *</Label>
            <input id="endpoint-tenant-id" type="text" required value={azureTenantId}
              onChange={(e) => setAzureTenantId(e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="flex h-9 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground font-mono placeholder:font-sans placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              disabled={initiating} />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="endpoint-operator-name">Operator Name</Label>
              <input id="endpoint-operator-name" type="text" value={operatorName}
                onChange={(e) => setOperatorName(e.target.value)} placeholder="operator"
                className="flex h-9 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                disabled={initiating} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="endpoint-operator-org">Operator Org</Label>
              <input id="endpoint-operator-org" type="text" value={operatorOrg}
                onChange={(e) => setOperatorOrg(e.target.value)} placeholder="FrostGate"
                className="flex h-9 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                disabled={initiating} />
            </div>
          </div>
          {initError && <Alert variant="destructive"><AlertDescription>{initError}</AlertDescription></Alert>}
          <Button type="submit" disabled={initiating || !azureTenantId.trim()} className="w-full sm:w-auto">
            {initiating ? 'Initiating…' : 'Run Endpoint Inventory Scan'}
          </Button>
        </form>
      )}
      {runId && runStatus && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${isComplete ? 'bg-success' : isFailed ? 'bg-danger' : 'bg-warning animate-pulse'}`} />
            <span className="text-sm text-foreground">{STATUS_LABELS[runStatus.status]}</span>
          </div>
          {(userCode || runStatus.user_code) && !isComplete && !isFailed && (
            <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
              <p className="text-xs font-semibold text-muted uppercase tracking-wider">Authentication Required</p>
              <p className="text-xs text-muted">Open the link below and enter the code when prompted.</p>
              <div className="flex items-center gap-2">
                <code className="text-2xl font-mono font-bold tracking-widest text-foreground bg-background rounded px-3 py-1.5 border border-border select-all">
                  {userCode ?? runStatus.user_code}
                </code>
                <Button type="button" variant="outline" onClick={handleCopy} className="text-xs h-8 px-3">
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
              {(verificationUri ?? runStatus.verification_uri) && (
                <a href={verificationUri ?? runStatus.verification_uri ?? '#'} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                  Open {verificationUri ?? runStatus.verification_uri}<span aria-hidden>↗</span>
                </a>
              )}
            </div>
          )}
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
