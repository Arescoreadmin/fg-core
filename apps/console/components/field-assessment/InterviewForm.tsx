'use client';

/**
 * InterviewForm — captures structured interview records as field observations.
 *
 * Backend mapping: POSTs to POST /observations with observation_type="interview"
 * and interview_role required. Interviews are NOT a separate entity — they are
 * FaFieldObservation records with interview_role populated. This is intentional:
 * interviews produce structured governance evidence in the same lineage as
 * technical observations. See docs/ai/PR_FIX_LOG.md PR 2 entry.
 */

import { useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Textarea } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type ObservationDomain, type ObservationSeverity, type Observation } from '@/lib/fieldAssessmentApi';

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

const CONFIDENCE_OPTIONS = [
  { value: 'high', label: 'High — subject was direct, evidence corroborated' },
  { value: 'medium', label: 'Medium — subject was uncertain or partial evidence' },
  { value: 'low', label: 'Low — anecdotal, unverified, or contradicted' },
];

interface Props {
  engagementId: string;
  onSuccess: (obs: Observation) => void;
}

export function InterviewForm({ engagementId, onSuccess }: Props) {
  const [interviewRole, setInterviewRole] = useState('');
  const [businessFunction, setBusinessFunction] = useState('');
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [aiUsageAsserted, setAiUsageAsserted] = useState('');
  const [policyAwareness, setPolicyAwareness] = useState('');
  const [structuredNotes, setStructuredNotes] = useState('');
  const [confidence, setConfidence] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastObs, setLastObs] = useState<Observation | null>(null);

  const canSubmit =
    interviewRole.trim() !== '' &&
    domain !== '' &&
    severity !== '' &&
    title.trim() !== '' &&
    structuredNotes.trim() !== '' &&
    !submitting;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);

    const description = [
      businessFunction.trim() && `Business function: ${businessFunction.trim()}`,
      aiUsageAsserted.trim() && `AI usage asserted: ${aiUsageAsserted.trim()}`,
      policyAwareness.trim() && `Policy awareness: ${policyAwareness.trim()}`,
      confidence && `Confidence: ${confidence}`,
      structuredNotes.trim(),
    ]
      .filter(Boolean)
      .join('\n\n');

    try {
      const obs = await fieldAssessmentApi.captureObservation(engagementId, {
        domain: domain as ObservationDomain,
        observation_type: 'interview',
        severity: severity as ObservationSeverity,
        title: title.trim(),
        description,
        interview_role: interviewRole.trim(),
      });
      setLastObs(obs);
      setInterviewRole('');
      setBusinessFunction('');
      setDomain('');
      setSeverity('');
      setTitle('');
      setAiUsageAsserted('');
      setPolicyAwareness('');
      setStructuredNotes('');
      setConfidence('');
      onSuccess(obs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Capture failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="interview-form">
      <div className="rounded border border-info/20 bg-info/5 px-3 py-2 text-xs text-info">
        Interview records are stored as structured field observations (type: interview) anchored to this engagement.
        Capture role — not personal name. Avoid PII beyond what governance evidence requires.
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-role">Interviewee Role / Title *</Label>
          <Input
            id="int-role"
            aria-required="true"
            placeholder="e.g., CTO, CISO, Data Steward"
            value={interviewRole}
            onChange={(e) => setInterviewRole(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-function">Business Function</Label>
          <Input
            id="int-function"
            placeholder="e.g., Engineering, Legal, Operations"
            value={businessFunction}
            onChange={(e) => setBusinessFunction(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-domain">Domain *</Label>
          <Select value={domain} onValueChange={(v) => setDomain(v as ObservationDomain)}>
            <SelectTrigger id="int-domain" aria-required="true">
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
          <Label htmlFor="int-severity">Governance Severity *</Label>
          <Select value={severity} onValueChange={(v) => setSeverity(v as ObservationSeverity)}>
            <SelectTrigger id="int-severity" aria-required="true">
              <SelectValue placeholder="Select severity…" />
            </SelectTrigger>
            <SelectContent>
              {(['critical', 'high', 'medium', 'low', 'info'] as ObservationSeverity[]).map((s) => (
                <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-title">Interview Summary Title *</Label>
        <Input
          id="int-title"
          aria-required="true"
          placeholder="e.g., CTO interview — AI adoption awareness"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-ai-usage">AI Usage Asserted</Label>
          <Input
            id="int-ai-usage"
            placeholder="e.g., Uses ChatGPT for draft communications"
            value={aiUsageAsserted}
            onChange={(e) => setAiUsageAsserted(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-policy">Policy Awareness</Label>
          <Input
            id="int-policy"
            placeholder="e.g., Aware of AI policy, did not read it"
            value={policyAwareness}
            onChange={(e) => setPolicyAwareness(e.target.value)}
          />
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-notes">Structured Notes *</Label>
        <Textarea
          id="int-notes"
          aria-required="true"
          placeholder="Key responses, evidence references, governance observations from this interview"
          className="min-h-[120px]"
          value={structuredNotes}
          onChange={(e) => setStructuredNotes(e.target.value)}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-confidence">Confidence Level</Label>
        <Select value={confidence} onValueChange={setConfidence}>
          <SelectTrigger id="int-confidence">
            <SelectValue placeholder="Select confidence…" />
          </SelectTrigger>
          <SelectContent>
            {CONFIDENCE_OPTIONS.map((c) => (
              <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {lastObs && (
        <Alert variant="success">
          <AlertDescription>Interview captured: <span className="font-medium">{lastObs.title}</span></AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Record interview">
        {submitting ? 'Recording…' : 'Record Interview'}
      </Button>
    </div>
  );
}
