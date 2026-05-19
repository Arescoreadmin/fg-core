'use client';

import { useState } from 'react';
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

interface Props {
  engagementId: string;
  onSuccess: (doc: DocumentAnalysis) => void;
}

export function DocumentRegistrationPanel({ engagementId, onSuccess }: Props) {
  const [documentName, setDocumentName] = useState('');
  const [classification, setClassification] = useState<DocumentClassification | ''>('');
  const [versionLabel, setVersionLabel] = useState('');
  const [approvedBy, setApprovedBy] = useState('');
  const [freshnessDate, setFreshnessDate] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDoc, setLastDoc] = useState<DocumentAnalysis | null>(null);

  const canSubmit = documentName.trim() !== '' && classification !== '' && !submitting;

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
      });
      setLastDoc(doc);
      setDocumentName('');
      setClassification('');
      setVersionLabel('');
      setApprovedBy('');
      setFreshnessDate('');
      onSuccess(doc);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Registration failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="document-registration-panel">
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
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Register document">
        {submitting ? 'Registering…' : 'Register Document'}
      </Button>
    </div>
  );
}
