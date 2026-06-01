'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@fg/ui';
import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { StatusBadge } from '@/components/field-assessment/StatusBadge';
import {
  fieldAssessmentApi,
  type Engagement,
  type AssessmentType,
  type CreateEngagementPayload,
} from '@/lib/fieldAssessmentApi';

const ASSESSMENT_TYPES: { value: AssessmentType; label: string }[] = [
  { value: 'ai_governance', label: 'AI Governance' },
  { value: 'cmmc', label: 'CMMC' },
  { value: 'hipaa', label: 'HIPAA' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO 27001' },
  { value: 'comprehensive', label: 'Comprehensive' },
];

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function CreateEngagementForm({ onCreated }: { onCreated: (e: Engagement) => void }) {
  const [clientName, setClientName] = useState('');
  const [clientDomain, setClientDomain] = useState('');
  const [assessmentType, setAssessmentType] = useState<AssessmentType | ''>('');
  const [assessorId, setAssessorId] = useState('');
  const [scheduledDate, setScheduledDate] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = clientName.trim() !== '' && assessmentType !== '' && assessorId.trim() !== '' && !submitting;

  async function handleCreate() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const payload: CreateEngagementPayload = {
        client_name: clientName.trim(),
        assessment_type: assessmentType as AssessmentType,
        assessor_id: assessorId.trim(),
      };
      if (clientDomain.trim()) payload.client_domain = clientDomain.trim();
      if (scheduledDate) payload.scheduled_date = scheduledDate;
      const eng = await fieldAssessmentApi.createEngagement(payload);
      setClientName('');
      setClientDomain('');
      setAssessmentType('');
      setAssessorId('');
      setScheduledDate('');
      onCreated(eng);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Creation failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">New Engagement</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="eng-client-name">Client / Org Name *</Label>
            <Input
              id="eng-client-name"
              aria-required="true"
              placeholder="Acme Corp"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-client-domain">Client Domain</Label>
            <Input
              id="eng-client-domain"
              placeholder="acme.com"
              value={clientDomain}
              onChange={(e) => setClientDomain(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-assessment-type">Assessment Type *</Label>
            <Select value={assessmentType} onValueChange={(v) => setAssessmentType(v as AssessmentType)}>
              <SelectTrigger id="eng-assessment-type" aria-required="true">
                <SelectValue placeholder="Select type…" />
              </SelectTrigger>
              <SelectContent>
                {ASSESSMENT_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-assessor-id">Assessor ID *</Label>
            <Input
              id="eng-assessor-id"
              aria-required="true"
              placeholder="assessor@firm.com"
              value={assessorId}
              onChange={(e) => setAssessorId(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="eng-scheduled-date">Scheduled Date</Label>
            <Input
              id="eng-scheduled-date"
              type="date"
              value={scheduledDate}
              onChange={(e) => setScheduledDate(e.target.value)}
            />
          </div>
        </div>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <Button onClick={handleCreate} disabled={!canSubmit} aria-label="Create engagement">
          {submitting ? 'Creating…' : 'Create Engagement'}
        </Button>
      </CardContent>
    </Card>
  );
}

export default function FieldAssessmentListPage() {
  const router = useRouter();
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState('__all__');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await fieldAssessmentApi.listEngagements(
        statusFilter !== '__all__' ? { status: statusFilter } : undefined,
      );
      setEngagements(page.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load engagements');
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  function handleCreated(eng: Engagement) {
    setShowCreate(false);
    setEngagements((prev) => [eng, ...prev]);
    router.push(`/field-assessment/${eng.id}`);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-foreground">Field Assessment Engagements</h1>
            <p className="text-sm text-muted mt-0.5">Operator console — Field Assessment Engagement Substrate</p>
          </div>
          <Button onClick={() => setShowCreate((v) => !v)} aria-label={showCreate ? 'Cancel' : 'New engagement'}>
            {showCreate ? 'Cancel' : 'New Engagement'}
          </Button>
        </div>

        {showCreate && <CreateEngagementForm onCreated={handleCreated} />}

        <div className="flex items-center gap-3">
          <Label htmlFor="status-filter" className="text-xs text-muted shrink-0">Filter by status</Label>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger id="status-filter" className="w-48 h-8 text-xs">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">All</SelectItem>
              {(['in_progress','delivered','remediation','monitoring','closed','cancelled'] as const).map((s) => (
                <SelectItem key={s} value={s} className="capitalize">{s.replace(/_/g, ' ')}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true" aria-label="Loading engagements">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {error && !loading && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!loading && !error && engagements.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-center text-muted">
            <p className="text-sm font-medium">No engagements found</p>
            <p className="text-xs mt-1">Create an engagement to begin field assessment collection</p>
          </div>
        )}

        {!loading && engagements.length > 0 && (
          <Table aria-label="engagements-table">
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Assessor</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {engagements.map((eng) => (
                <TableRow
                  key={eng.id}
                  className="cursor-pointer"
                  onClick={() => router.push(`/field-assessment/${eng.id}`)}
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && router.push(`/field-assessment/${eng.id}`)}
                  aria-label={`Open engagement: ${eng.client_name}`}
                >
                  <TableCell>
                    <div className="font-medium text-foreground">{eng.client_name}</div>
                    {eng.client_domain && <div className="text-xs text-muted">{eng.client_domain}</div>}
                  </TableCell>
                  <TableCell className="text-xs capitalize">{eng.assessment_type.replace(/_/g, ' ')}</TableCell>
                  <TableCell><StatusBadge status={eng.status} /></TableCell>
                  <TableCell className="text-xs text-muted">{eng.assessor_id}</TableCell>
                  <TableCell className="text-xs text-muted">{formatDate(eng.created_at)}</TableCell>
                  <TableCell className="text-xs text-muted">{formatDate(eng.updated_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
