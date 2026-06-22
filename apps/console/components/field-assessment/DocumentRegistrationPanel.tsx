'use client';

import { useEffect, useRef, useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type DocumentClassification, type DocumentAnalysis } from '@/lib/fieldAssessmentApi';

const CLASSIFICATIONS: { value: DocumentClassification; label: string }[] = [
  { value: 'ai_policy', label: 'AI Policy' },
  { value: 'data_governance', label: 'Data Governance' },
  { value: 'incident_response', label: 'Incident Response' },
  { value: 'vendor_risk', label: 'Vendor Risk' },
  { value: 'access_control', label: 'Access Control' },
  { value: 'training_records', label: 'Training Records' },
  { value: 'audit_reports', label: 'Audit Reports' },
  { value: 'other', label: 'Other' },
];

const CLASSIFICATION_LABELS: Partial<Record<DocumentClassification, string>> = {
  ai_policy: 'AI Policy',
  data_governance: 'Data Governance',
  incident_response: 'Incident Response',
  vendor_risk: 'Vendor Risk',
  access_control: 'Access Control',
  training_records: 'Training Records',
  audit_reports: 'Audit Reports',
};

async function hashFile(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface Props {
  engagementId: string;
  prefill?: { classification?: DocumentClassification } | null;
  onSuccess: (doc: DocumentAnalysis) => void;
}

export function DocumentRegistrationPanel({ engagementId, prefill, onSuccess }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [documentName, setDocumentName] = useState('');
  const [classification, setClassification] = useState<DocumentClassification | ''>('');
  const [versionLabel, setVersionLabel] = useState('');
  const [approvedBy, setApprovedBy] = useState('');
  const [freshnessDate, setFreshnessDate] = useState('');
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [hashing, setHashing] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [noPolicyMode, setNoPolicyMode] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDoc, setLastDoc] = useState<DocumentAnalysis | null>(null);

  // Apply prefill when guided execution sends a classification hint.
  useEffect(() => {
    if (!prefill) return;
    if (prefill.classification) setClassification(prefill.classification);
  }, [prefill]);

  // When no-policy mode is toggled on, build a sensible document name.
  useEffect(() => {
    if (noPolicyMode) {
      const classLabel = classification
        ? (CLASSIFICATION_LABELS[classification as DocumentClassification] ?? classification)
        : 'Policy';
      setDocumentName(`No ${classLabel} currently in place — Gap Acknowledged`);
      setApprovedBy('Assessor attestation');
      setVersionLabel('GAP');
      clearFile();
    } else {
      setDocumentName('');
      setApprovedBy('');
      setVersionLabel('');
    }
  }, [noPolicyMode]); // eslint-disable-line react-hooks/exhaustive-deps

  const canSubmit = documentName.trim() !== '' && classification !== '' && !submitting && !hashing;

  async function processFile(file: File) {
    setHashing(true);
    setError(null);
    setFileHash(null);
    setFileName(file.name);
    setFileSize(file.size);
    if (!documentName.trim()) setDocumentName(file.name);
    try {
      const hash = await hashFile(file);
      setFileHash(hash);
    } catch {
      setError('Failed to read file — please try again.');
    } finally {
      setHashing(false);
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processFile(file);
  }

  function clearFile() {
    setFileHash(null);
    setFileName(null);
    setFileSize(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const doc = await fieldAssessmentApi.registerDocument(engagementId, {
        document_name: documentName.trim(),
        document_classification: classification as DocumentClassification,
        version_label: versionLabel.trim() || undefined,
        approved_by: approvedBy.trim() || undefined,
        freshness_date: freshnessDate || undefined,
        document_hash: fileHash || undefined,
      });
      setLastDoc(doc);
      setDocumentName('');
      setClassification('');
      setVersionLabel('');
      setApprovedBy('');
      setFreshnessDate('');
      setNoPolicyMode(false);
      clearFile();
      onSuccess(doc);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Registration failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="document-registration-panel">
      {/* No-policy toggle */}
      <div className="flex items-center justify-between rounded border border-border bg-surface-2 px-3 py-2">
        <div>
          <p className="text-xs font-medium text-foreground">No policy currently exists</p>
          <p className="text-[11px] text-muted">Document the gap — records that no policy is in place at time of assessment</p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={noPolicyMode}
          onClick={() => setNoPolicyMode((v) => !v)}
          className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-primary/40 ${
            noPolicyMode ? 'bg-primary' : 'bg-surface-3'
          }`}
        >
          <span
            className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
              noPolicyMode ? 'translate-x-4' : 'translate-x-0'
            }`}
          />
        </button>
      </div>

      {/* File drop zone — hidden in no-policy mode */}
      {!noPolicyMode && (
        <div
          role="button"
          tabIndex={0}
          aria-label="Upload policy file"
          className={`relative flex flex-col items-center justify-center gap-2 rounded border-2 border-dashed p-6 text-center transition-colors cursor-pointer
            ${dragOver ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50 hover:bg-surface-2'}`}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => e.key === 'Enter' && fileInputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="sr-only"
            accept=".pdf,.doc,.docx,.txt,.xlsx,.xls,.pptx,.ppt,.png,.jpg,.jpeg"
            onChange={handleFileChange}
            aria-label="Select policy file"
          />
          {hashing ? (
            <p className="text-sm text-muted animate-pulse">Computing integrity hash…</p>
          ) : fileName ? (
            <div className="space-y-1 w-full">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-foreground truncate">{fileName}</span>
                <button
                  type="button"
                  className="text-xs text-muted hover:text-foreground shrink-0"
                  onClick={(e) => { e.stopPropagation(); clearFile(); }}
                  aria-label="Remove file"
                >
                  ✕ Remove
                </button>
              </div>
              {fileSize !== null && (
                <p className="text-xs text-muted">{(fileSize / 1024).toFixed(1)} KB</p>
              )}
              {fileHash && (
                <p className="text-xs text-muted font-mono truncate" title={fileHash}>
                  SHA-256: {fileHash.slice(0, 16)}…
                </p>
              )}
            </div>
          ) : (
            <>
              <p className="text-sm text-muted">
                <span className="font-medium text-foreground">Click to upload</span> or drag and drop
              </p>
              <p className="text-xs text-muted">PDF, Word, Excel, PowerPoint, images — max 50 MB</p>
            </>
          )}
        </div>
      )}

      {/* Gap acknowledgement notice */}
      {noPolicyMode && (
        <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
          This will register a gap acknowledgement — no file required. The assessor attestation confirms no policy existed at time of assessment.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1 sm:col-span-2">
          <Label htmlFor="doc-name">Document Name *</Label>
          <Input
            id="doc-name"
            aria-required="true"
            placeholder="e.g., AI Usage Policy v2.1.pdf"
            value={documentName}
            onChange={(e) => setDocumentName(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="doc-classification">Classification *</Label>
          <Select value={classification} onValueChange={(v) => setClassification(v as DocumentClassification)}>
            <SelectTrigger id="doc-classification" aria-required="true">
              <SelectValue placeholder="Select classification…" />
            </SelectTrigger>
            <SelectContent>
              {CLASSIFICATIONS.map((c) => (
                <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="doc-version">Version Label</Label>
          <Input
            id="doc-version"
            placeholder="e.g., v2.1"
            value={versionLabel}
            onChange={(e) => setVersionLabel(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="doc-approved-by">Approved By</Label>
          <Input
            id="doc-approved-by"
            placeholder="Approver name or role"
            value={approvedBy}
            onChange={(e) => setApprovedBy(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="doc-freshness">Freshness / Review Date</Label>
          <Input
            id="doc-freshness"
            type="date"
            value={freshnessDate}
            onChange={(e) => setFreshnessDate(e.target.value)}
          />
        </div>
      </div>

      {lastDoc && (
        <Alert variant="success">
          <AlertDescription>
            Registered: <span className="font-medium">{lastDoc.document_name}</span>
            {lastDoc.document_hash && (
              <span className="ml-2 font-mono text-xs text-muted">({lastDoc.document_hash.slice(0, 8)}…)</span>
            )}
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Register document">
        {submitting ? 'Registering…' : noPolicyMode ? 'Record Gap' : 'Register Document'}
      </Button>
    </div>
  );
}
