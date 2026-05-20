'use client';

import { useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@fg/ui';
import { fieldAssessmentApi, type EvidenceEntityType, type EvidenceLink } from '@/lib/fieldAssessmentApi';

// ---------------------------------------------------------------------------
// Evidence lineage SVG graph (inline — no external deps)
// ---------------------------------------------------------------------------

const NODE_W = 140;
const NODE_H = 40;
const H_GAP = 90;
const V_GAP = 54;
const PAD = 16;

function truncate(s: string, max = 16): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function EvidenceLineageGraph({ links }: { links: EvidenceLink[] }) {
  // Collect unique source and evidence nodes
  const sourceKeys = Array.from(new Set(links.map((l) => `${l.source_entity_type}:${l.source_entity_id}`)));
  const evidenceKeys = Array.from(new Set(links.map((l) => `${l.evidence_entity_type}:${l.evidence_entity_id}`)));

  const svgW = 2 * NODE_W + H_GAP + 2 * PAD;
  const svgH = Math.max(sourceKeys.length, evidenceKeys.length) * V_GAP + 2 * PAD + NODE_H;

  function sourceY(i: number) { return PAD + i * V_GAP; }
  function evidenceY(i: number) { return PAD + i * V_GAP; }
  const srcX = PAD;
  const evX = PAD + NODE_W + H_GAP;

  return (
    <div className="space-y-1" aria-label="evidence-lineage-graph">
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Lineage Graph</p>
      <div className="overflow-x-auto rounded border border-border bg-surface-2 p-2">
        <svg
          width={svgW}
          height={svgH}
          aria-label="Evidence lineage visualization"
          className="block"
        >
          {/* Edges */}
          {links.map((l, i) => {
            const si = sourceKeys.indexOf(`${l.source_entity_type}:${l.source_entity_id}`);
            const ei = evidenceKeys.indexOf(`${l.evidence_entity_type}:${l.evidence_entity_id}`);
            const x1 = srcX + NODE_W;
            const y1 = sourceY(si) + NODE_H / 2;
            const x2 = evX;
            const y2 = evidenceY(ei) + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            return (
              <path
                key={i}
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
                strokeOpacity="0.25"
                markerEnd="url(#arrowhead)"
              />
            );
          })}
          {/* Arrowhead marker */}
          <defs>
            <marker id="arrowhead" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="currentColor" opacity="0.4" />
            </marker>
          </defs>
          {/* Source nodes */}
          {sourceKeys.map((k, i) => {
            const [type, id] = k.split(':');
            return (
              <g key={k} transform={`translate(${srcX},${sourceY(i)})`}>
                <rect width={NODE_W} height={NODE_H} rx="4" fill="transparent" stroke="currentColor" strokeOpacity="0.2" strokeWidth="1" />
                <text x="8" y="14" fontSize="8" fill="currentColor" opacity="0.5" fontFamily="monospace">{type}</text>
                <text x="8" y="27" fontSize="10" fill="currentColor" opacity="0.8" fontFamily="monospace">{truncate(id)}</text>
              </g>
            );
          })}
          {/* Evidence nodes */}
          {evidenceKeys.map((k, i) => {
            const [type, id] = k.split(':');
            return (
              <g key={k} transform={`translate(${evX},${evidenceY(i)})`}>
                <rect width={NODE_W} height={NODE_H} rx="4" fill="transparent" stroke="currentColor" strokeOpacity="0.2" strokeWidth="1" />
                <text x="8" y="14" fontSize="8" fill="currentColor" opacity="0.5" fontFamily="monospace">{type}</text>
                <text x="8" y="27" fontSize="10" fill="currentColor" opacity="0.8" fontFamily="monospace">{truncate(id)}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

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
        <div className="space-y-4">
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

          <EvidenceLineageGraph links={existingLinks} />
        </div>
      )}
    </div>
  );
}
