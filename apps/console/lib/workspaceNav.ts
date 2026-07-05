/**
 * Canonical cross-workspace navigation map.
 * Defines which workspaces link to which others.
 *
 * Supported context keys (all WorkspaceContextKey values):
 * tenant, engagement, assessment, report, finding, remediation,
 * policy, decision, timelinePosition, framework, control, evidence,
 * customer, simulation, replay
 *
 * Self-link guard: callers filter by currentWorkspace before rendering
 * to prevent self-referential navigation links.
 */

import type { WorkspaceContextKey } from './workspaceContext';

export interface WorkspaceNavLink {
  id: string;
  label: string;
  route: string;
  mcimId: string;
  description: string;
  contextParams?: WorkspaceContextKey[];
}

export const WORKSPACE_NAV_MAP: Record<string, WorkspaceNavLink[]> = {
  'executive-intelligence': [
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'View trust graph and verification status',
      contextParams: ['tenant'],
    },
    {
      id: 'operations',
      label: 'Operations Workspace',
      route: '/workspace',
      mcimId: 'MCIM-18.6-OPS-WS',
      description: 'Real-time operational health',
      contextParams: ['tenant'],
    },
    {
      id: 'field-assessments',
      label: 'Field Assessments',
      route: '/field-assessment',
      mcimId: 'MCIM-18.6-FIELD-ASSESS',
      description: 'Active field engagements',
      contextParams: ['tenant', 'engagement'],
    },
    {
      id: 'reports',
      label: 'Assessment Reports',
      route: '/reports',
      mcimId: 'MCIM-18.6-REPORTS',
      description: 'Delivered reports',
      contextParams: ['tenant', 'report'],
    },
    {
      id: 'remediation',
      label: 'Remediation',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Remediation tracking',
      contextParams: ['tenant', 'finding'],
    },
    {
      id: 'customer-portal',
      label: 'Customer Portal',
      route: '/dashboard/alignment',
      mcimId: 'MCIM-18.6-ALIGNMENT',
      description: 'Customer-facing views',
      contextParams: ['tenant', 'customer'],
    },
  ],

  'trust-center': [
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6-EXEC-INTEL',
      description: 'Executive posture and risk metrics',
      contextParams: ['tenant'],
    },
    {
      id: 'operations',
      label: 'Operations Workspace',
      route: '/workspace',
      mcimId: 'MCIM-18.6-OPS-WS',
      description: 'Real-time operational health',
      contextParams: ['tenant'],
    },
    {
      id: 'field-assessments',
      label: 'Field Assessments',
      route: '/field-assessment',
      mcimId: 'MCIM-18.6-FIELD-ASSESS',
      description: 'Active field engagements',
      contextParams: ['tenant', 'engagement'],
    },
    {
      id: 'forensics',
      label: 'Forensics & Remediation',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Findings and remediation tracking',
      contextParams: ['tenant', 'finding'],
    },
    {
      id: 'decisions',
      label: 'Decision Ledger',
      route: '/dashboard/decisions',
      mcimId: 'MCIM-18.6-DECISIONS',
      description: 'Governance decision records',
      contextParams: ['tenant', 'decision'],
    },
  ],

  'operations-workspace': [
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6-EXEC-INTEL',
      description: 'Executive posture and risk metrics',
      contextParams: ['tenant'],
    },
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'View trust graph and verification status',
      contextParams: ['tenant'],
    },
    {
      id: 'field-assessments',
      label: 'Field Assessments',
      route: '/field-assessment',
      mcimId: 'MCIM-18.6-FIELD-ASSESS',
      description: 'Active field engagements',
      contextParams: ['tenant', 'engagement'],
    },
    {
      id: 'decisions',
      label: 'Decision Ledger',
      route: '/dashboard/decisions',
      mcimId: 'MCIM-18.6-DECISIONS',
      description: 'Governance decision records',
      contextParams: ['tenant', 'decision'],
    },
    {
      id: 'forensics',
      label: 'Forensics & Remediation',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Findings and remediation tracking',
      contextParams: ['tenant', 'finding'],
    },
  ],

  'field-assessments': [
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'View trust graph and verification status',
      contextParams: ['tenant'],
    },
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6-EXEC-INTEL',
      description: 'Executive posture and risk metrics',
      contextParams: ['tenant'],
    },
    {
      id: 'reports',
      label: 'Assessment Reports',
      route: '/reports',
      mcimId: 'MCIM-18.6-REPORTS',
      description: 'Delivered reports',
      contextParams: ['tenant', 'engagement', 'report'],
    },
    {
      id: 'forensics',
      label: 'Forensics & Remediation',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Findings and remediation tracking',
      contextParams: ['tenant', 'engagement', 'finding'],
    },
  ],

  'reports': [
    {
      id: 'field-assessments',
      label: 'Field Assessments',
      route: '/field-assessment',
      mcimId: 'MCIM-18.6-FIELD-ASSESS',
      description: 'Active field engagements',
      contextParams: ['tenant', 'engagement'],
    },
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'View trust graph and verification status',
      contextParams: ['tenant'],
    },
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6-EXEC-INTEL',
      description: 'Executive posture and risk metrics',
      contextParams: ['tenant'],
    },
    {
      id: 'remediation',
      label: 'Remediation',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Remediation tracking linked to findings',
      contextParams: ['tenant', 'finding'],
    },
    {
      id: 'customer-portal',
      label: 'Customer Portal',
      route: '/dashboard/alignment',
      mcimId: 'MCIM-18.6-ALIGNMENT',
      description: 'Share report with customer',
      contextParams: ['tenant', 'report', 'customer'],
    },
  ],

  'governance-intelligence': [
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6.7-EXEC-INTEL',
      description: 'Executive posture and strategic metrics',
      contextParams: ['tenant', 'framework', 'control', 'policy'],
    },
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'Trust verification and evidence graph',
      contextParams: ['tenant', 'evidence', 'assessment'],
    },
    {
      id: 'forensics',
      label: 'Forensics & Timeline',
      route: '/dashboard/forensics',
      mcimId: 'MCIM-18.6-FORENSICS',
      description: 'Replay and timeline investigation',
      contextParams: ['tenant', 'timelinePosition', 'simulation', 'replay'],
    },
    {
      id: 'readiness',
      label: 'Readiness',
      route: '/dashboard/readiness',
      mcimId: 'MCIM-18.6-READINESS',
      description: 'AI readiness and remediation posture',
      contextParams: ['tenant', 'remediation', 'finding'],
    },
  ],

  'command-center': [
    {
      id: 'executive-intelligence',
      label: 'Executive Intelligence',
      route: '/dashboard/executive',
      mcimId: 'MCIM-18.6-EXEC-INTEL',
      description: 'Executive posture and risk metrics',
      contextParams: ['tenant'],
    },
    {
      id: 'trust-center',
      label: 'Trust Center',
      route: '/trust-center',
      mcimId: 'MCIM-18.6-TRUST',
      description: 'View trust graph and verification status',
      contextParams: ['tenant'],
    },
    {
      id: 'operations-workspace',
      label: 'Operations Workspace',
      route: '/workspace',
      mcimId: 'MCIM-18.6-OPS-WS',
      description: 'Real-time operational health',
      contextParams: ['tenant'],
    },
    {
      id: 'field-assessments',
      label: 'Field Assessments',
      route: '/field-assessment',
      mcimId: 'MCIM-18.6-FIELD-ASSESS',
      description: 'Active field engagements',
      contextParams: ['tenant', 'engagement'],
    },
    {
      id: 'decisions',
      label: 'Decision Ledger',
      route: '/dashboard/decisions',
      mcimId: 'MCIM-18.6-DECISIONS',
      description: 'Governance decision records',
      contextParams: ['tenant', 'decision'],
    },
    {
      id: 'reports',
      label: 'Assessment Reports',
      route: '/reports',
      mcimId: 'MCIM-18.6-REPORTS',
      description: 'Delivered and draft reports',
      contextParams: ['tenant', 'report'],
    },
  ],
};
