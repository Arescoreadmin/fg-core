'use client';

import { useState } from 'react';
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

export function ObservationForm({ engagementId, onSuccess }: Props) {
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [obsType, setObsType] = useState<ObservationType | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [linkedFindingIds, setLinkedFindingIds] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastObs, setLastObs] = useState<Observation | null>(null);

  const canSubmit =
    domain !== '' &&
    obsType !== '' &&
    severity !== '' &&
    title.trim() !== '' &&
    description.trim() !== '' &&
    !submitting;

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
      });
      setLastObs(obs);
      setDomain('');
      setObsType('');
      setSeverity('');
      setTitle('');
      setDescription('');
      setLinkedFindingIds('');
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
