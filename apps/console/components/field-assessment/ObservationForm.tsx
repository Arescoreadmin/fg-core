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

const SEVERITIES: { value: ObservationSeverity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

// Type options with plain-English guidance so a new auditor can pick confidently.
const TYPES: { value: ObservationType; label: string; description: string }[] = [
  { value: 'gap',      label: 'Gap',      description: 'A control, policy, or process that is missing or incomplete' },
  { value: 'concern',  label: 'Concern',  description: 'Something that warrants attention but is not yet a confirmed gap' },
  { value: 'finding',  label: 'Finding',  description: 'A confirmed issue with clear evidence — will become a formal finding' },
  { value: 'strength', label: 'Strength', description: 'Something the organisation is doing well that reduces risk' },
  { value: 'note',     label: 'Note',     description: 'General context or background information for the record' },
];

export interface ObservationPrefill {
  domain?: ObservationDomain;
  obsType?: ObservationType;
  title?: string;
  instruction?: string;
}

interface Props {
  engagementId: string;
  prefill?: ObservationPrefill | null;
  onSuccess: (obs: Observation) => void;
}

interface KvPair {
  key: string;
  value: string;
}

export function ObservationForm({ engagementId, prefill, onSuccess }: Props) {
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [obsType, setObsType] = useState<ObservationType | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [kvPairs, setKvPairs] = useState<KvPair[]>([]);
  const [advancedOpen, setAdvancedOpen] = useState(false);
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
      if (Array.isArray(draft.kvPairs)) setKvPairs(draft.kvPairs as KvPair[]);
      setHasDraft(true);
    });
  }, [engagementId]);

  // Apply prefill when guided execution sends context
  useEffect(() => {
    if (!prefill) return;
    if (prefill.domain) setDomain(prefill.domain);
    if (prefill.obsType) setObsType(prefill.obsType);
    if (prefill.title) setTitle(prefill.title);
  }, [prefill]);

  // Auto-save draft
  useEffect(() => {
    if (!domain && !obsType && !title && !description) return;
    saveDraft('observation', engagementId, { domain, obsType, severity, title, description, kvPairs });
  }, [engagementId, domain, obsType, severity, title, description, kvPairs]);

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
        linked_finding_ids: [],
        structured_evidence: buildStructuredEvidence(),
      });
      setLastObs(obs);
      setDomain('');
      setObsType('');
      setSeverity('');
      setTitle('');
      setDescription('');
      setKvPairs([]);
      setAdvancedOpen(false);
      setHasDraft(false);
      clearDraft('observation', engagementId);
      onSuccess(obs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Capture failed');
    } finally {
      setSubmitting(false);
    }
  }

  const selectedType = TYPES.find((t) => t.value === obsType);

  return (
    <div className="space-y-4" aria-label="observation-form">

      {/* Guided execution context banner */}
      {prefill?.instruction && (
        <div className="rounded border border-primary/30 bg-primary/5 px-3 py-2">
          <p className="text-xs font-semibold text-foreground">From guided execution</p>
          <p className="text-[11px] text-muted mt-0.5">{prefill.instruction}</p>
        </div>
      )}

      {/* Row 1 — Domain + Severity */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="obs-domain">Domain *</Label>
          <Select value={domain} onValueChange={(v) => setDomain(v as ObservationDomain)}>
            <SelectTrigger id="obs-domain" aria-required="true">
              <SelectValue placeholder="What area does this relate to?" />
            </SelectTrigger>
            <SelectContent>
              {DOMAINS.map((d) => (
                <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="obs-severity">Severity *</Label>
          <Select value={severity} onValueChange={(v) => setSeverity(v as ObservationSeverity)}>
            <SelectTrigger id="obs-severity" aria-required="true">
              <SelectValue placeholder="How serious is this?" />
            </SelectTrigger>
            <SelectContent>
              {SEVERITIES.map((s) => (
                <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Row 2 — Type with descriptions */}
      <div className="space-y-1">
        <Label htmlFor="obs-type">Type *</Label>
        <Select value={obsType} onValueChange={(v) => setObsType(v as ObservationType)}>
          <SelectTrigger id="obs-type" aria-required="true">
            <SelectValue placeholder="What kind of observation is this?" />
          </SelectTrigger>
          <SelectContent>
            {TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                <span className="font-medium">{t.label}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {selectedType && (
          <p className="text-[11px] text-muted">{selectedType.description}</p>
        )}
      </div>

      {/* Row 3 — What you observed */}
      <div className="space-y-1">
        <Label htmlFor="obs-title">What did you observe? *</Label>
        <Input
          id="obs-title"
          aria-required="true"
          placeholder="One clear sentence — e.g. 'No AI usage policy exists' or 'MFA enforced on all AI tools'"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      {/* Row 4 — Detail */}
      <div className="space-y-1">
        <Label htmlFor="obs-description">Detail and context *</Label>
        <Textarea
          id="obs-description"
          aria-required="true"
          placeholder="Describe what you saw, heard, or reviewed. Include who confirmed it and any relevant context."
          className="min-h-[100px]"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      {/* Advanced — structured evidence key-value (collapsed by default) */}
      <div className="rounded border border-border">
        <button
          type="button"
          className="flex w-full items-center justify-between px-3 py-2 text-left focus:outline-none"
          onClick={() => setAdvancedOpen((v) => !v)}
          aria-expanded={advancedOpen}
        >
          <span className="text-xs text-muted">Advanced — structured evidence fields</span>
          <span className="text-xs text-muted">{advancedOpen ? '▲' : '▼'}</span>
        </button>

        {advancedOpen && (
          <div className="border-t border-border px-3 pb-3 pt-2 space-y-2" aria-label="structured-evidence-editor">
            <p className="text-[11px] text-muted">
              Optional key-value pairs for machine-readable evidence — e.g. policy_version: 2.1, last_reviewed: 2023-01-15
            </p>
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
            <button
              type="button"
              onClick={addKvPair}
              className="text-xs text-primary hover:underline focus-visible:outline-none"
            >
              + Add field
            </button>
          </div>
        )}
      </div>

      {hasDraft && (
        <Alert variant="info">
          <AlertDescription className="text-xs">Draft restored from previous session.</AlertDescription>
        </Alert>
      )}

      {lastObs && (
        <Alert variant="success">
          <AlertDescription>
            Captured: <span className="font-medium">{lastObs.title}</span>
            {(lastObs.observation_type === 'finding' || lastObs.observation_type === 'gap') && (
              <span className="ml-2 text-[11px] text-muted">— review the Findings tab to link evidence</span>
            )}
          </AlertDescription>
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
