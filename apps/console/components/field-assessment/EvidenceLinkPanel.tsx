'use client';

import { useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@fg/ui';
import { fieldAssessmentApi, type EvidenceEntityType, type EvidenceLink } from '@/lib/fieldAssessmentApi';

const EVIDENCE_TYPES: { value: EvidenceEntityType; label: string }[] = [
  { value: 'scan_result', label: 'Scan Result' },
  { value: 'document_analysis', label: 'Document Analysis' },
  { value: 'field_observation', label: 'Field Observation' },
  { value: 'attestation', label: 'Attestation' },
];

interface Props {
  engagementId: string;
  existingLinks: EvidenceLink[];
  onSuccess: (link: EvidenceLink) => void;
}

export function EvidenceLinkPanel({ engagementId, existingLinks, onSuccess }: Props) {
  const [sourceEntityType, setSourceEntityType] = useState('');
  const [sourceEntityId, setSourceEntityId] = useState('');
  const [evidenceEntityType, setEvidenceEntityType] = useState<EvidenceEntityType | ''>('');
  const [evidenceEntityId, setEvidenceEntityId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit =
    sourceEntityType.trim() !== '' &&
    sourceEntityId.trim() !== '' &&
    evidenceEntityType !== '' &&
    evidenceEntityId.trim() !== '' &&
    !submitting;

  // Prevent duplicate submission (UI-side guard; backend is authoritative)
  const isDuplicate = existingLinks.some(
    (l) =>
      l.source_entity_type === sourceEntityType &&
      l.source_entity_id === sourceEntityId &&
      l.evidence_entity_type === evidenceEntityType &&
      l.evidence_entity_id === evidenceEntityId,
  );

  async function handleSubmit() {
    if (!canSubmit || isDuplicate) return;
    setSubmitting(true);
    setError(null);
    try {
      const link = await fieldAssessmentApi.createEvidenceLink(engagementId, {
        source_entity_type: sourceEntityType.trim(),
        source_entity_id: sourceEntityId.trim(),
        evidence_entity_type: evidenceEntityType as EvidenceEntityType,
        evidence_entity_id: evidenceEntityId.trim(),
      });
      setSourceEntityType('');
      setSourceEntityId('');
      setEvidenceEntityType('');
      setEvidenceEntityId('');
      onSuccess(link);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Link creation failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6" aria-label="evidence-link-panel">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="ev-source-type">Source Entity Type *</Label>
          <Input
            id="ev-source-type"
            aria-required="true"
            placeholder="e.g., normalized_finding"
            value={sourceEntityType}
            onChange={(e) => setSourceEntityType(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="ev-source-id">Source Entity ID *</Label>
          <Input
            id="ev-source-id"
            aria-required="true"
            placeholder="Entity ID"
            value={sourceEntityId}
            onChange={(e) => setSourceEntityId(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="ev-evidence-type">Evidence Entity Type *</Label>
          <Select value={evidenceEntityType} onValueChange={(v) => setEvidenceEntityType(v as EvidenceEntityType)}>
            <SelectTrigger id="ev-evidence-type" aria-required="true">
              <SelectValue placeholder="Select type…" />
            </SelectTrigger>
            <SelectContent>
              {EVIDENCE_TYPES.map((t) => (
                <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="ev-evidence-id">Evidence Entity ID *</Label>
          <Input
            id="ev-evidence-id"
            aria-required="true"
            placeholder="Evidence record ID"
            value={evidenceEntityId}
            onChange={(e) => setEvidenceEntityId(e.target.value)}
          />
        </div>
      </div>

      {isDuplicate && (
        <Alert variant="warning">
          <AlertDescription>This evidence link already exists for this engagement.</AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button
        onClick={handleSubmit}
        disabled={!canSubmit || isDuplicate}
        aria-label="Create evidence link"
      >
        {submitting ? 'Linking…' : 'Create Evidence Link'}
      </Button>

      {existingLinks.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted uppercase tracking-wider">
            Existing Links ({existingLinks.length})
          </p>
          <Table aria-label="evidence-links-table">
            <TableHeader>
              <TableRow>
                <TableHead>Source Type</TableHead>
                <TableHead>Source ID</TableHead>
                <TableHead>Evidence Type</TableHead>
                <TableHead>Evidence ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {existingLinks.map((l) => (
                <TableRow key={l.id}>
                  <TableCell className="font-mono text-xs">{l.source_entity_type}</TableCell>
                  <TableCell className="font-mono text-xs truncate max-w-[120px]">{l.source_entity_id}</TableCell>
                  <TableCell className="font-mono text-xs">{l.evidence_entity_type}</TableCell>
                  <TableCell className="font-mono text-xs truncate max-w-[120px]">{l.evidence_entity_id}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
