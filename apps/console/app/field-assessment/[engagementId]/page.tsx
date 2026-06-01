'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@fg/ui';
import { StatusBadge } from '@/components/field-assessment/StatusBadge';
import { StatusTransitionBar } from '@/components/field-assessment/StatusTransitionBar';
import { GuidedExecutionPanel } from '@/components/field-assessment/GuidedExecutionPanel';
import { ScanImportPanel } from '@/components/field-assessment/ScanImportPanel';
import { MsgraphScanPanel } from '@/components/field-assessment/MsgraphScanPanel';
import { OauthInventoryScanPanel } from '@/components/field-assessment/OauthInventoryScanPanel';
import { EndpointInventoryScanPanel } from '@/components/field-assessment/EndpointInventoryScanPanel';
import { NetworkScanPanel } from '@/components/field-assessment/NetworkScanPanel';
import { DnsEmailScanPanel } from '@/components/field-assessment/DnsEmailScanPanel';
import { WebHeadersScanPanel } from '@/components/field-assessment/WebHeadersScanPanel';
import { EntraGovernanceScanPanel } from '@/components/field-assessment/EntraGovernanceScanPanel';
import { SharepointScanPanel } from '@/components/field-assessment/SharepointScanPanel';
import { OauthRiskScanPanel } from '@/components/field-assessment/OauthRiskScanPanel';
import { DocumentRegistrationPanel } from '@/components/field-assessment/DocumentRegistrationPanel';
import { ObservationForm } from '@/components/field-assessment/ObservationForm';
import { InterviewForm } from '@/components/field-assessment/InterviewForm';
import { EvidenceLinkPanel } from '@/components/field-assessment/EvidenceLinkPanel';
import { FindingPreviewPanel } from '@/components/field-assessment/FindingPreviewPanel';
import { EngagementSummaryPanel } from '@/components/field-assessment/EngagementSummaryPanel';
import { ReportGenerationPanel } from '@/components/field-assessment/ReportGenerationPanel';
import { ReportVersionHistory } from '@/components/field-assessment/ReportVersionHistory';
import { ReportViewer } from '@/components/field-assessment/ReportViewer';
import { ReportExportBar } from '@/components/field-assessment/ReportExportBar';
import { ControlGapMatrix } from '@/components/field-assessment/ControlGapMatrix';
import { QuestionnairePanel } from '@/components/field-assessment/QuestionnairePanel';
import {
  fieldAssessmentApi,
  type Engagement,
  type EngagementStatus,
  type EngagementSummary,
  type ScanResultSummary,
  type DocumentAnalysis,
  type Observation,
  type Finding,
  type EvidenceLink,
  type AuditEvent,
  type ExecutionState,
  type ReportDocument,
} from '@/lib/fieldAssessmentApi';

const TAB_SECTIONS: Record<string, string> = {
  total_scan_results: 'scans',
  total_document_analyses: 'documents',
  total_observations: 'observations',
  total_evidence_links: 'evidence',
  total_findings: 'findings',
  report: 'reports',
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export default function EngagementWorkspacePage() {
  const params = useParams();
  const router = useRouter();
  const engagementId = params.engagementId as string;

  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [summary, setSummary] = useState<EngagementSummary | null>(null);
  const [scans, setScans] = useState<ScanResultSummary[]>([]);
  const [documents, setDocuments] = useState<DocumentAnalysis[]>([]);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidenceLinks, setEvidenceLinks] = useState<EvidenceLink[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [executionState, setExecutionState] = useState<ExecutionState | null>(null);

  const [engLoading, setEngLoading] = useState(true);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [executionLoading, setExecutionLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);
  const [engError, setEngError] = useState<string | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState('overview');
  const [expandedObsId, setExpandedObsId] = useState<string | null>(null);
  const mainTabsRef = useRef<HTMLElement>(null);

  const [reportsRefreshKey, setReportsRefreshKey] = useState(0);
  const [selectedReportVersion, setSelectedReportVersion] = useState<number | null>(null);
  const [reportDoc, setReportDoc] = useState<ReportDocument | null>(null);
  const [reportDocLoading, setReportDocLoading] = useState(false);
  const [reportDocError, setReportDocError] = useState<string | null>(null);
  const loadReportDocSeqRef = useRef(0);

  const loadEngagement = useCallback(async () => {
    setEngLoading(true);
    setEngError(null);
    try {
      const eng = await fieldAssessmentApi.getEngagement(engagementId);
      setEngagement(eng);
    } catch (e) {
      setEngError(e instanceof Error ? e.message : 'Failed to load engagement');
    } finally {
      setEngLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    if (!engagement) return;
    const prev = document.title;
    document.title = `${engagement.client_name} — FrostGate`;
    return () => { document.title = prev; };
  }, [engagement]);

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const s = await fieldAssessmentApi.getSummary(engagementId);
      setSummary(s);
    } catch (e) {
      setSummaryError(e instanceof Error ? e.message : 'Failed to load summary');
    } finally {
      setSummaryLoading(false);
    }
  }, [engagementId]);

  const loadCollections = useCallback(async () => {
    const [scanRes, docRes, obsRes, linkRes] = await Promise.allSettled([
      fieldAssessmentApi.listScans(engagementId),
      fieldAssessmentApi.listDocuments(engagementId),
      fieldAssessmentApi.listObservations(engagementId),
      fieldAssessmentApi.listEvidenceLinks(engagementId),
    ]);
    if (scanRes.status === 'fulfilled') setScans(scanRes.value);
    if (docRes.status === 'fulfilled') setDocuments(docRes.value);
    if (obsRes.status === 'fulfilled') setObservations(obsRes.value);
    if (linkRes.status === 'fulfilled') setEvidenceLinks(linkRes.value);
  }, [engagementId]);

  const loadExecutionState = useCallback(async () => {
    setExecutionLoading(true);
    setExecutionError(null);
    try {
      const state = await fieldAssessmentApi.getExecutionState(engagementId);
      setExecutionState(state);
    } catch (e) {
      setExecutionError(e instanceof Error ? e.message : 'Failed to load execution state');
    } finally {
      setExecutionLoading(false);
    }
  }, [engagementId]);

  const loadFindings = useCallback(async () => {
    setFindingsLoading(true);
    setFindingsError(null);
    try {
      const page = await fieldAssessmentApi.listFindings(engagementId);
      setFindings(page.items);
    } catch (e) {
      setFindingsError(e instanceof Error ? e.message : 'Failed to load findings');
    } finally {
      setFindingsLoading(false);
    }
  }, [engagementId]);

  const loadAuditEvents = useCallback(async () => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const events = await fieldAssessmentApi.listAuditEvents(engagementId);
      setAuditEvents(events);
    } catch (e) {
      setAuditError(e instanceof Error ? e.message : 'Failed to load audit history');
    } finally {
      setAuditLoading(false);
    }
  }, [engagementId]);

  const loadReportDoc = useCallback(async (version: number) => {
    const seq = ++loadReportDocSeqRef.current;
    setReportDocLoading(true);
    setReportDocError(null);
    try {
      const doc = await fieldAssessmentApi.getReport(engagementId, version);
      if (seq !== loadReportDocSeqRef.current) return;
      setReportDoc(doc);
    } catch {
      if (seq !== loadReportDocSeqRef.current) return;
      setReportDocError('Failed to load report.');
    } finally {
      if (seq !== loadReportDocSeqRef.current) return;
      setReportDocLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    const tab = new URLSearchParams(window.location.search).get('tab');
    if (tab) setActiveTab(tab);
  }, []);

  useEffect(() => {
    loadEngagement();
    loadSummary();
    loadCollections();
    loadExecutionState();
  }, [loadEngagement, loadSummary, loadCollections, loadExecutionState]);

  useEffect(() => {
    if (activeTab === 'findings') loadFindings();
    if (activeTab === 'history') loadAuditEvents();
    // Scroll the active tab trigger into view when switching tabs programmatically
    // (the tab bar is overflow-x-auto so the active trigger may be off-screen).
    mainTabsRef.current
      ?.querySelector('[role="tab"][data-state="active"]')
      ?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  }, [activeTab, loadFindings, loadAuditEvents]);

  useEffect(() => {
    if (selectedReportVersion !== null) {
      loadReportDoc(selectedReportVersion);
    }
  }, [selectedReportVersion, loadReportDoc]);

  async function handleTransition(newStatus: EngagementStatus, reason: string) {
    const updated = await fieldAssessmentApi.transitionEngagement(engagementId, { new_status: newStatus, reason });
    setEngagement(updated);
    loadSummary();
    loadExecutionState();
  }

  function handleSectionClick(key: string) {
    const tab = TAB_SECTIONS[key] ?? key;
    if (tab) {
      setActiveTab(tab);
      mainTabsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  if (engLoading) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <div className="max-w-6xl mx-auto px-4 py-8 space-y-4">
          <div className="h-8 w-48 bg-surface-2 rounded animate-pulse" />
          <div className="h-32 bg-surface-2 rounded animate-pulse" />
        </div>
      </div>
    );
  }

  if (engError || !engagement) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <Alert variant="destructive">
            <AlertDescription>{engError ?? 'Engagement not found'}</AlertDescription>
          </Alert>
          <button
            className="mt-4 text-sm text-muted hover:text-foreground underline"
            onClick={() => router.push('/field-assessment')}
          >
            ← Back to engagements
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">

        {/* Header */}
        <div className="space-y-1">
          <button
            className="text-xs text-muted hover:text-foreground transition-colors"
            onClick={() => router.push('/field-assessment')}
          >
            ← Field Assessments
          </button>
          <div className="flex flex-wrap items-start gap-3">
            <div className="flex-1 min-w-0">
              <h1 className="text-lg font-semibold text-foreground truncate">{engagement.client_name}</h1>
              <div className="flex flex-wrap items-center gap-2 mt-1">
                {engagement.client_domain && (
                  <span className="text-xs text-muted">{engagement.client_domain}</span>
                )}
                <span className="text-xs text-muted capitalize">{engagement.assessment_type.replace(/_/g, ' ')}</span>
                <span className="text-xs text-muted">Assessor: {engagement.assessor_id}</span>
              </div>
            </div>
            <StatusBadge status={engagement.status} />
          </div>
        </div>

        {/* Status transition */}
        <StatusTransitionBar
          currentStatus={engagement.status}
          onTransition={handleTransition}
        />

        {/* Metadata */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs text-muted">
          <div><span className="font-medium text-foreground block">Engagement ID</span><span className="font-mono">{engagement.id}</span></div>
          <div><span className="font-medium text-foreground block">Schema Version</span>{engagement.schema_version}</div>
          <div><span className="font-medium text-foreground block">Created</span>{formatDate(engagement.created_at)}</div>
          <div><span className="font-medium text-foreground block">Last Updated</span>{formatDate(engagement.updated_at)}</div>
        </div>

        {/* Main workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

          {/* Sidebar: guided execution + summary stats */}
          <aside className="lg:col-span-1 space-y-4">
            <Card className="border-border">
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-sm">Guided Execution Panel</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <GuidedExecutionPanel
                  engagementId={engagementId}
                  executionState={executionState}
                  loading={executionLoading}
                  error={executionError}
                  onSectionClick={handleSectionClick}
                />
              </CardContent>
            </Card>

            {summary && (
              <Card className="border-border">
                <CardHeader className="pb-2 pt-3 px-4">
                  <CardTitle className="text-sm">Aggregate Counts</CardTitle>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  <EngagementSummaryPanel
                    summary={summary}
                    loading={summaryLoading}
                    error={summaryError}
                  />
                </CardContent>
              </Card>
            )}
          </aside>

          {/* Main tabs */}
          <main ref={mainTabsRef} className="lg:col-span-3">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="overflow-x-auto">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="scans">Scans ({scans.length})</TabsTrigger>
                <TabsTrigger value="documents">Documents ({documents.length})</TabsTrigger>
                <TabsTrigger value="observations">Observations ({observations.filter((o) => o.observation_type !== 'interview').length})</TabsTrigger>
                <TabsTrigger value="interviews">Interviews</TabsTrigger>
                <TabsTrigger value="evidence">Evidence Links ({evidenceLinks.length})</TabsTrigger>
                <TabsTrigger value="findings">Findings</TabsTrigger>
                <TabsTrigger value="questionnaire">Questionnaire</TabsTrigger>
                <TabsTrigger value="history">History</TabsTrigger>
                <TabsTrigger value="reports">Reports</TabsTrigger>
              </TabsList>

              {/* Overview */}
              <TabsContent value="overview">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Engagement Overview</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-4 space-y-4">
                    {engagement.scheduled_date && (
                      <div className="text-sm">
                        <span className="text-muted">Scheduled: </span>
                        <span className="text-foreground">{engagement.scheduled_date}</span>
                      </div>
                    )}
                    {Object.keys(engagement.engagement_metadata).length > 0 && (
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider">Engagement Metadata</p>
                        <pre className="text-xs font-mono bg-surface-2 rounded p-3 overflow-auto max-h-40 text-foreground">
                          {JSON.stringify(engagement.engagement_metadata, null, 2)}
                        </pre>
                      </div>
                    )}
                    <p className="text-xs text-muted">
                      Use the tabs above to capture scans, documents, observations, interviews, and evidence links during the field assessment.
                    </p>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Scans */}
              <TabsContent value="scans">
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run MS Graph Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — authenticate in browser, scan runs automatically
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <MsgraphScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run Entra ID Governance Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — PIM roles, Access Reviews, Identity Protection, Conditional Access
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <EntraGovernanceScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run SharePoint &amp; OneDrive Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — anonymous links, external sharing, no-expiry links
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <SharepointScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run OAuth Inventory Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — enumerates OAuth apps, grants, and service principals
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <OauthInventoryScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run OAuth Risk Deep Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — illicit consent grants, AI tool data access, write-all permissions
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <OauthRiskScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run Endpoint Inventory Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Device-code flow — enumerates Azure AD devices and Intune managed endpoints
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <EndpointInventoryScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border mb-4">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run Network Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Port scan + TLS inspection — no authentication required
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <NetworkScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run DNS &amp; Email Security Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      DMARC, SPF, DKIM, MX, and DNSSEC — no authentication required
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <DnsEmailScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Run Web Security Headers Scan</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      HSTS, CSP, X-Frame-Options, Referrer-Policy — no authentication required
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <WebHeadersScanPanel
                      engagementId={engagementId}
                      onSuccess={() => {
                        fieldAssessmentApi.listScans(engagementId).then(setScans).catch(() => {});
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Import Scan Result</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Paste a previously-exported scan result JSON
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <ScanImportPanel
                      engagementId={engagementId}
                      onSuccess={(scan) => {
                        setScans((prev) => [scan, ...prev]);
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                {scans.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider">Imported Scans ({scans.length})</p>
                    {scans.map((s) => (
                      <div key={s.id} className="flex flex-wrap items-center gap-3 p-3 rounded border border-border bg-surface-2 text-xs">
                        <span className="font-medium text-foreground capitalize">{s.source_type.replace(/_/g, ' ')}</span>
                        <span className="text-muted">Objects: {s.object_count}</span>
                        <span className="text-muted font-mono truncate max-w-[140px]">Hash: {s.evidence_hash}</span>
                        <span className="text-muted ml-auto">{new Date(s.collected_at).toLocaleDateString()}</span>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>

              {/* Documents */}
              <TabsContent value="documents">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Register Document</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <DocumentRegistrationPanel
                      engagementId={engagementId}
                      onSuccess={(doc) => {
                        setDocuments((prev) => [doc, ...prev]);
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                {documents.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider">Registered Documents ({documents.length})</p>
                    {documents.map((d) => (
                      <div key={d.id} className="flex flex-wrap items-center gap-3 p-3 rounded border border-border bg-surface-2 text-xs">
                        <span className="font-medium text-foreground">{d.document_name}</span>
                        <span className="text-muted capitalize">{d.document_classification.replace(/_/g, ' ')}</span>
                        {d.version_label && <span className="text-muted">{d.version_label}</span>}
                        {d.approved_by && <span className="text-muted">Approved: {d.approved_by}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>

              {/* Observations */}
              <TabsContent value="observations">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Capture Observation</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <ObservationForm
                      engagementId={engagementId}
                      onSuccess={(obs) => {
                        setObservations((prev) => [obs, ...prev]);
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                {observations.filter((o) => o.observation_type !== 'interview').length > 0 && (
                  <div className="mt-4 space-y-2">
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider">
                      Recorded Observations ({observations.filter((o) => o.observation_type !== 'interview').length})
                    </p>
                    {observations
                      .filter((o) => o.observation_type !== 'interview')
                      .map((o) => {
                        const isExpanded = expandedObsId === o.id;
                        return (
                          <div
                            key={o.id}
                            className="p-3 rounded border border-border bg-surface-2 space-y-1 text-xs cursor-pointer"
                            onClick={() => setExpandedObsId(isExpanded ? null : o.id)}
                            role="button"
                            aria-expanded={isExpanded}
                            tabIndex={0}
                            onKeyDown={(e) => e.key === 'Enter' && setExpandedObsId(isExpanded ? null : o.id)}
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-medium text-foreground">{o.title}</span>
                              <span className="capitalize text-muted">{o.severity}</span>
                              <span className="capitalize text-muted">{o.observation_type.replace(/_/g, ' ')}</span>
                              <span className="ml-auto text-muted">{isExpanded ? '▲' : '▼'}</span>
                            </div>
                            <p className={`text-muted ${isExpanded ? '' : 'line-clamp-2'}`}>{o.description}</p>
                            {isExpanded && (
                              <div className="border-t border-border pt-2 mt-2 space-y-1">
                                <div className="flex flex-wrap gap-3">
                                  <span className="text-muted">Domain: <span className="text-foreground capitalize">{o.domain.replace(/_/g, ' ')}</span></span>
                                  <span className="text-muted">Assessor: <span className="text-foreground">{o.assessor_id}</span></span>
                                </div>
                                {o.linked_finding_ids.length > 0 && (
                                  <div>
                                    <span className="text-muted">Linked findings: </span>
                                    <span className="font-mono text-foreground">{o.linked_finding_ids.join(', ')}</span>
                                  </div>
                                )}
                                {Object.keys(o.structured_evidence).length > 0 && (
                                  <div className="space-y-0.5">
                                    <p className="text-muted font-semibold">Structured evidence:</p>
                                    {Object.entries(o.structured_evidence).map(([k, v]) => (
                                      <div key={k} className="font-mono">
                                        <span className="text-muted">{k}: </span>
                                        <span className="text-foreground">{String(v)}</span>
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                  </div>
                )}
              </TabsContent>

              {/* Interviews */}
              <TabsContent value="interviews">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Record Interview</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <InterviewForm
                      engagementId={engagementId}
                      onSuccess={(obs) => {
                        setObservations((prev) => [obs, ...prev]);
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
                {observations.filter((o) => o.observation_type === 'interview').length > 0 && (
                  <div className="mt-4 space-y-2">
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider">
                      Recorded Interviews ({observations.filter((o) => o.observation_type === 'interview').length})
                    </p>
                    {observations
                      .filter((o) => o.observation_type === 'interview')
                      .map((o) => (
                        <div key={o.id} className="p-3 rounded border border-border bg-surface-2 space-y-1 text-xs">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium text-foreground">{o.title}</span>
                            {o.interview_role && (
                              <span className="text-info">{o.interview_role}</span>
                            )}
                            <span className="capitalize text-muted">{o.domain.replace(/_/g, ' ')}</span>
                          </div>
                          <p className="text-muted line-clamp-2">{o.description}</p>
                        </div>
                      ))}
                  </div>
                )}
              </TabsContent>

              {/* Evidence Links */}
              <TabsContent value="evidence">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Evidence Linkage</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <EvidenceLinkPanel
                      engagementId={engagementId}
                      existingLinks={evidenceLinks}
                      onSuccess={(link) => {
                        setEvidenceLinks((prev) => [link, ...prev]);
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Findings (read-only) */}
              <TabsContent value="findings">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Normalized Findings</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Findings are normalized by the governance substrate — not created in this UI
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <FindingPreviewPanel
                      findings={findings}
                      engagementId={engagementId}
                      loading={findingsLoading}
                      error={findingsError}
                      onRemediationSaved={() => fieldAssessmentApi.listFindings(engagementId).then(r => setFindings(r.items)).catch(() => {})}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* NIST AI RMF Questionnaire */}
              <TabsContent value="questionnaire">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">NIST AI RMF Questionnaire</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Structured per-control evidence capture — 69 subcategories across GOVERN, MAP, MEASURE, MANAGE
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    <QuestionnairePanel
                      engagementId={engagementId}
                      onSubmitted={() => {
                        loadSummary();
                        loadExecutionState();
                      }}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Audit History (append-only; read-only surface) */}
              <TabsContent value="history">
                <Card className="border-border">
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Audit History</CardTitle>
                    <p className="text-xs text-muted mt-0.5">
                      Append-only event log — all mutations recorded by the governance substrate
                    </p>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    {auditLoading && (
                      <div className="space-y-2" aria-busy="true">
                        {[1, 2, 3].map((i) => (
                          <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
                        ))}
                      </div>
                    )}
                    {auditError && !auditLoading && (
                      <Alert variant="destructive">
                        <AlertDescription>{auditError}</AlertDescription>
                      </Alert>
                    )}
                    {!auditLoading && !auditError && auditEvents.length === 0 && (
                      <div className="flex flex-col items-center justify-center py-12 text-center text-muted">
                        <p className="text-sm font-medium">No audit events yet</p>
                        <p className="text-xs mt-1">Events are recorded automatically on every mutation</p>
                      </div>
                    )}
                    {!auditLoading && auditEvents.length > 0 && (
                      <div className="space-y-2" aria-label="audit-event-list">
                        {auditEvents.map((ev) => (
                          <div key={ev.id} className="p-3 rounded border border-border bg-surface-2 text-xs space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono font-medium text-foreground">{ev.event_type}</span>
                              <span className="text-muted">{ev.actor}</span>
                              <span className="ml-auto text-muted font-mono">{formatDate(ev.created_at)}</span>
                            </div>
                            <div className="text-muted">
                              Code: <span className="font-mono text-foreground">{ev.reason_code}</span>
                            </div>
                            {Object.keys(ev.payload).length > 0 && (
                              <pre className="text-xs font-mono bg-background rounded p-2 overflow-auto max-h-24 text-muted">
                                {JSON.stringify(ev.payload, null, 2)}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
              {/* Reports */}
              <TabsContent value="reports">
                <div className="space-y-4">
                  <Card className="border-border">
                    <CardHeader className="pb-2 pt-4 px-4">
                      <CardTitle className="text-sm">Generate Report</CardTitle>
                      <p className="text-xs text-muted mt-0.5">
                        Signed, versioned governance deliverables — all generation is backend-authoritative
                      </p>
                    </CardHeader>
                    <CardContent className="px-4 pb-4">
                      <ReportGenerationPanel
                        engagementId={engagementId}
                        onGenerated={() => {
                          setReportsRefreshKey((k) => k + 1);
                          setSelectedReportVersion(null);
                          setReportDoc(null);
                        }}
                      />
                    </CardContent>
                  </Card>

                  <ReportVersionHistory
                    engagementId={engagementId}
                    refreshKey={reportsRefreshKey}
                    selectedVersion={selectedReportVersion}
                    onSelectVersion={setSelectedReportVersion}
                    onQaApproved={() => { loadSummary(); loadExecutionState(); }}
                  />

                  {selectedReportVersion !== null && (
                    <>
                      <ReportExportBar
                        engagementId={engagementId}
                        version={selectedReportVersion}
                        reportType={reportDoc?.report_type ?? null}
                      />
                      <ReportViewer
                        document={reportDoc}
                        loading={reportDocLoading}
                        error={reportDocError}
                        engagementId={engagementId}
                        onShowEvidence={() => setActiveTab('evidence')}
                      />
                      <ControlGapMatrix
                        data={
                          reportDoc
                            ? (reportDoc.report?.framework_summary as Record<string, string[]> | null)
                            : null
                        }
                      />
                    </>
                  )}
                </div>
              </TabsContent>

            </Tabs>
          </main>
        </div>
      </div>
    </div>
  );
}
