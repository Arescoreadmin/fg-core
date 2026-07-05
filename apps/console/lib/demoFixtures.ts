/**
 * Demo fixture data — deterministic seed data for demo mode.
 * Deterministic only — no randomness, no live timestamps. All dates are fixed ISO strings.
 *
 * DEMO FIXTURE — not production data
 */

// Feature flag — off by default; enable for demo/sales environments
export const DEMO_MODE_ACTIVE = false;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DemoEngagement {
  id: string;
  name: string;
  tenant: string;
  status: string;
  framework: string;
  created_at: string;
}

export interface DemoFinding {
  id: string;
  title: string;
  severity: string;
  status: string;
  engagement_id: string;
  control_id: string;
}

export interface DemoReport {
  id: string;
  title: string;
  engagement_id: string;
  status: string;
  created_at: string;
}

export interface DemoRemediation {
  id: string;
  title: string;
  finding_id: string;
  status: string;
  priority: string;
  due_date: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DEMO_TENANT_ID = 'demo-tenant-acme-corp-2026'; // DEMO FIXTURE — not production data

// ---------------------------------------------------------------------------
// Engagements — 5 entries
// ---------------------------------------------------------------------------

export const DEMO_ENGAGEMENTS: DemoEngagement[] = [
  // DEMO FIXTURE — not production data
  {
    id: 'demo-eng-001',
    name: 'Acme Corp — SOC 2 Type II Assessment',
    tenant: DEMO_TENANT_ID,
    status: 'active',
    framework: 'SOC 2',
    created_at: '2026-01-15T09:00:00.000Z',
  },
  {
    id: 'demo-eng-002',
    name: 'Acme Corp — ISO 27001 Gap Analysis',
    tenant: DEMO_TENANT_ID,
    status: 'active',
    framework: 'ISO 27001',
    created_at: '2026-02-01T10:30:00.000Z',
  },
  {
    id: 'demo-eng-003',
    name: 'Acme Corp — NIST CSF Readiness Review',
    tenant: DEMO_TENANT_ID,
    status: 'completed',
    framework: 'NIST CSF',
    created_at: '2025-10-20T08:00:00.000Z',
  },
  {
    id: 'demo-eng-004',
    name: 'Acme Corp — PCI DSS Scoping Workshop',
    tenant: DEMO_TENANT_ID,
    status: 'draft',
    framework: 'PCI DSS',
    created_at: '2026-03-10T14:00:00.000Z',
  },
  {
    id: 'demo-eng-005',
    name: 'Acme Corp — HIPAA Security Rule Assessment',
    tenant: DEMO_TENANT_ID,
    status: 'active',
    framework: 'HIPAA',
    created_at: '2026-04-05T11:00:00.000Z',
  },
];

// ---------------------------------------------------------------------------
// Findings — 10 entries
// ---------------------------------------------------------------------------

export const DEMO_FINDINGS: DemoFinding[] = [
  // DEMO FIXTURE — not production data
  { id: 'demo-fnd-001', title: 'MFA not enforced on privileged accounts', severity: 'critical', status: 'open', engagement_id: 'demo-eng-001', control_id: 'CC6.1' },
  { id: 'demo-fnd-002', title: 'Encryption at rest missing on secondary datastore', severity: 'high', status: 'open', engagement_id: 'demo-eng-001', control_id: 'CC9.2' },
  { id: 'demo-fnd-003', title: 'Vulnerability scan cadence below policy threshold', severity: 'medium', status: 'in-remediation', engagement_id: 'demo-eng-001', control_id: 'CC7.1' },
  { id: 'demo-fnd-004', title: 'Access review not completed within SLA', severity: 'medium', status: 'in-remediation', engagement_id: 'demo-eng-001', control_id: 'CC6.3' },
  { id: 'demo-fnd-005', title: 'Logging gaps detected in edge service', severity: 'high', status: 'open', engagement_id: 'demo-eng-002', control_id: 'A.12.4.1' },
  { id: 'demo-fnd-006', title: 'Supplier risk assessments not documented', severity: 'medium', status: 'open', engagement_id: 'demo-eng-002', control_id: 'A.15.1.1' },
  { id: 'demo-fnd-007', title: 'Incident response plan not tested in 12 months', severity: 'high', status: 'open', engagement_id: 'demo-eng-002', control_id: 'A.16.1.1' },
  { id: 'demo-fnd-008', title: 'Password policy does not meet complexity requirements', severity: 'low', status: 'closed', engagement_id: 'demo-eng-003', control_id: 'PR.AC-1' },
  { id: 'demo-fnd-009', title: 'Network segmentation controls insufficient', severity: 'critical', status: 'open', engagement_id: 'demo-eng-005', control_id: '164.312(a)(1)' },
  { id: 'demo-fnd-010', title: 'PHI data flows not fully inventoried', severity: 'high', status: 'in-remediation', engagement_id: 'demo-eng-005', control_id: '164.308(a)(1)' },
];

// ---------------------------------------------------------------------------
// Reports — 5 entries
// ---------------------------------------------------------------------------

export const DEMO_REPORTS: DemoReport[] = [
  // DEMO FIXTURE — not production data
  { id: 'demo-rpt-001', title: 'SOC 2 Type II Interim Report — Q1 2026', engagement_id: 'demo-eng-001', status: 'draft', created_at: '2026-04-01T12:00:00.000Z' },
  { id: 'demo-rpt-002', title: 'ISO 27001 Gap Analysis Summary', engagement_id: 'demo-eng-002', status: 'delivered', created_at: '2026-03-15T09:30:00.000Z' },
  { id: 'demo-rpt-003', title: 'NIST CSF Readiness — Final Report', engagement_id: 'demo-eng-003', status: 'delivered', created_at: '2025-12-10T16:00:00.000Z' },
  { id: 'demo-rpt-004', title: 'PCI DSS Scoping — Initial Findings', engagement_id: 'demo-eng-004', status: 'draft', created_at: '2026-04-20T10:00:00.000Z' },
  { id: 'demo-rpt-005', title: 'HIPAA Security Rule — Preliminary Assessment', engagement_id: 'demo-eng-005', status: 'draft', created_at: '2026-05-01T08:00:00.000Z' },
];

// ---------------------------------------------------------------------------
// Remediations — 8 entries
// ---------------------------------------------------------------------------

export const DEMO_REMEDIATIONS: DemoRemediation[] = [
  // DEMO FIXTURE — not production data
  { id: 'demo-rem-001', title: 'Enable MFA on all privileged accounts', finding_id: 'demo-fnd-001', status: 'in-progress', priority: 'critical', due_date: '2026-05-30T00:00:00.000Z' },
  { id: 'demo-rem-002', title: 'Enable encryption at rest on secondary datastore', finding_id: 'demo-fnd-002', status: 'not-started', priority: 'high', due_date: '2026-06-15T00:00:00.000Z' },
  { id: 'demo-rem-003', title: 'Increase vulnerability scan frequency to weekly', finding_id: 'demo-fnd-003', status: 'in-progress', priority: 'medium', due_date: '2026-05-15T00:00:00.000Z' },
  { id: 'demo-rem-004', title: 'Complete access review backlog', finding_id: 'demo-fnd-004', status: 'in-progress', priority: 'medium', due_date: '2026-05-20T00:00:00.000Z' },
  { id: 'demo-rem-005', title: 'Expand logging coverage to edge services', finding_id: 'demo-fnd-005', status: 'not-started', priority: 'high', due_date: '2026-06-30T00:00:00.000Z' },
  { id: 'demo-rem-006', title: 'Document and assess top 20 suppliers', finding_id: 'demo-fnd-006', status: 'not-started', priority: 'medium', due_date: '2026-07-31T00:00:00.000Z' },
  { id: 'demo-rem-007', title: 'Schedule and conduct IR tabletop exercise', finding_id: 'demo-fnd-007', status: 'not-started', priority: 'high', due_date: '2026-06-30T00:00:00.000Z' },
  { id: 'demo-rem-008', title: 'Implement network segmentation per HIPAA requirements', finding_id: 'demo-fnd-009', status: 'in-progress', priority: 'critical', due_date: '2026-06-01T00:00:00.000Z' },
];

// ---------------------------------------------------------------------------
// Aggregate metrics
// ---------------------------------------------------------------------------

// DEMO FIXTURE — not production data
export const DEMO_EXECUTIVE_METRICS = {
  posture_score: 73,
  risk_count: 14,
  compliance_score: 82,
  confidence: 0.87,
} as const;

// DEMO FIXTURE — not production data
export const DEMO_TRUST_SCORE = {
  overall: 0.91,
  evidence_coverage: 0.88,
  verification_rate: 0.95,
} as const;

// DEMO FIXTURE — not production data
export const DEMO_CUSTOMER_PORTALS = [
  { customer: 'Acme Corp', engagement_id: 'demo-eng-001', status: 'active' },
  { customer: 'Acme Corp', engagement_id: 'demo-eng-002', status: 'active' },
  { customer: 'Acme Corp', engagement_id: 'demo-eng-003', status: 'archived' },
  { customer: 'Acme Corp', engagement_id: 'demo-eng-005', status: 'active' },
] as const;
