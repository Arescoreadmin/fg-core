'use client';

import { useEffect, useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Textarea } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import {
  fieldAssessmentApi,
  type ObservationDomain,
  type ObservationType,
  type ObservationSeverity,
  type Observation,
} from '@/lib/fieldAssessmentApi';
import { saveDraft, loadDraft, clearDraft } from '@/lib/fieldAssessmentDrafts';

const DOMAINS: { value: ObservationDomain; label: string }[] = [
  { value: 'ai_governance', label: 'AI Governance' },
  { value: 'data_security', label: 'Data Security' },
  { value: 'access_management', label: 'Access Management' },
  { value: 'operational_security', label: 'Operational Security' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'vendor_management', label: 'Vendor Management' },
  { value: 'incident_response', label: 'Incident Response' },
  { value: 'training', label: 'Training' },
];

const TYPES: { value: ObservationType; label: string }[] = [
  { value: 'gap', label: 'Gap' },
  { value: 'strength', label: 'Strength' },
  { value: 'concern', label: 'Concern' },
  { value: 'finding', label: 'Finding' },
  { value: 'note', label: 'Note' },
];

const SEVERITIES: { value: ObservationSeverity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

interface Props {
  engagementId: string;
  onSuccess: (obs: Observation) => void;
}

interface KvPair {
  key: string;
  value: string;
}

export function ObservationForm({ engagementId, onSuccess }: Props) {
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [obsType, setObsType] = useState<ObservationType | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [linkedFindingIds, setLinkedFindingIds] = useState('');
  const [kvPairs, setKvPairs] = useState<KvPair[]>([]);
  const [hasDraft, setHasDraft] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastObs, setLastObs] = useState<Observation | null>(null);

  // Restore draft on mount
  useEffect(() => {
    loadDraft('observation', engagementId).then((draft) => {
      if (!draft) return;
      if (draft.domain) setDomain(draft.domain as ObservationDomain);
      if (draft.obsType) setObsType(draft.obsType as ObservationType);
      if (draft.severity) setSeverity(draft.severity as ObservationSeverity);
      if (draft.title) setTitle(draft.title as string);
      if (draft.description) setDescription(draft.description as string);
      if (draft.linkedFindingIds) setLinkedFindingIds(draft.linkedFindingIds as string);
      if (Array.isArray(draft.kvPairs)) setKvPairs(draft.kvPairs as KvPair[]);
      setHasDraft(true);
    });
  }, [engagementId]);

  // Auto-save draft on field changes (debounced via useEffect dependency)
  useEffect(() => {
    if (!domain && !obsType && !title && !description) return;
    saveDraft('observation', engagementId, { domain, obsType, severity, title, description, linkedFindingIds, kvPairs });
  }, [engagementId, domain, obsType, severity, title, description, linkedFindingIds, kvPairs]);

  const canSubmit =
    domain !== '' &&
    obsType !== '' &&
    severity !== '' &&
    title.trim() !== '' &&
    description.trim() !== '' &&
    !submitting;

  function addKvPair() {
    setKvPairs((prev) => [...prev, { key: '', value: '' }]);
  }

  function updateKvPair(index: number, field: 'key' | 'value', val: string) {
    setKvPairs((prev) => prev.map((p, i) => (i === index ? { ...p, [field]: val } : p)));
  }

  function removeKvPair(index: number) {
    setKvPairs((prev) => prev.filter((_, i) => i !== index));
  }

  function buildStructuredEvidence(): Record<string, string> {
    const ev: Record<string, string> = {};
    for (const { key, value } of kvPairs) {
      if (key.trim()) ev[key.trim()] = value;
    }
    return ev;
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const obs = await fieldAssessmentApi.captureObservation(engagementId, {
        domain: domain as ObservationDomain,
        observation_type: obsType as ObservationType,
        severity: severity as ObservationSeverity,
        title: title.trim(),
        description: description.trim(),
        linked_finding_ids: linkedFindingIds
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        structured_evidence: buildStructuredEvidence(),
      });
      setLastObs(obs);
      setDomain('');
      setObsType('');
      setSeverity('');
      setTitle('');
      setDescription('');
      setLinkedFindingIds('');
      setKvPairs([]);
      setHasDraft(false);
      clearDraft('observation', engagementId);
      onSuccess(obs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Capture failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="observation-form">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="space-y-1">
          <Label htmlFor="obs-domain">Domain *</Label>
          <Select value={domain} onValueChange={(v) => setDomain(v as ObservationDomain)}>
            <SelectTrigger id="obs-domain" aria-required="true">
              <SelectValue placeholder="Select domain…" />
            </SelectTrigger>
            <SelectContent>
              {DOMAINS.map((d) => (
                <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="obs-type">Type *</Label>
          <Select value={obsType} onValueChange={(v) => setObsType(v as ObservationType)}>
            <SelectTrigger id="obs-type" aria-required="true">
              <SelectValue placeholder="Select type…" />
            </SelectTrigger>
            <SelectContent>
              {TYPES.map((t) => (
                <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="obs-severity">Severity *</Label>
          <Select value={severity} onValueChange={(v) => setSeverity(v as ObservationSeverity)}>
            <SelectTrigger id="obs-severity" aria-required="true">
              <SelectValue placeholder="Select severity…" />
            </SelectTrigger>
            <SelectContent>
              {SEVERITIES.map((s) => (
                <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="obs-title">Title / Summary *</Label>
        <Input
          id="obs-title"
          aria-required="true"
          placeholder="Brief, structured observation title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="obs-description">Description *</Label>
        <Textarea
          id="obs-description"
          aria-required="true"
          placeholder="Structured description of the observation, evidence observed, and context"
          className="min-h-[100px]"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="obs-findings">Linked Finding IDs (comma-separated)</Label>
        <Input
          id="obs-findings"
          placeholder="finding-id-1, finding-id-2"
          value={linkedFindingIds}
          onChange={(e) => setLinkedFindingIds(e.target.value)}
        />
      </div>

      <div className="space-y-2" aria-label="structured-evidence-editor">
        <div className="flex items-center justify-between">
          <Label className="text-xs">Structured Evidence (key-value)</Label>
          <button
            type="button"
            onClick={addKvPair}
            className="text-xs text-primary hover:underline focus-visible:outline-none"
          >
            + Add field
          </button>
        </div>
        {kvPairs.map((pair, i) => (
          <div key={i} className="flex gap-2 items-center">
            <Input
              placeholder="key"
              className="flex-1 text-xs"
              value={pair.key}
              onChange={(e) => updateKvPair(i, 'key', e.target.value)}
              aria-label={`Evidence key ${i + 1}`}
            />
            <Input
              placeholder="value"
              className="flex-1 text-xs"
              value={pair.value}
              onChange={(e) => updateKvPair(i, 'value', e.target.value)}
              aria-label={`Evidence value ${i + 1}`}
            />
            <button
              type="button"
              onClick={() => removeKvPair(i)}
              className="text-xs text-muted hover:text-danger shrink-0 focus-visible:outline-none"
              aria-label="Remove field"
            >
              ✕
            </button>
          </div>
        ))}
      </div>

      {hasDraft && (
        <Alert variant="info">
          <AlertDescription className="text-xs">Draft restored from previous session.</AlertDescription>
        </Alert>
      )}

      {lastObs && (
        <Alert variant="success">
          <AlertDescription>Observation captured: <span className="font-medium">{lastObs.title}</span></AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Capture observation">
        {submitting ? 'Capturing…' : 'Capture Observation'}
      </Button>
    </div>
  );
}
