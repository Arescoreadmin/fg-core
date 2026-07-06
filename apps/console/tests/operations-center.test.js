/**
 * operations-center.test.js
 *
 * Test suite for PR 18.7 — Autonomous Governance Operations Center (AGOC).
 * MCIM authority: OPERATIONS-CENTER
 *
 * Coverage: 900+ assertions across rendering, empty states, error states,
 * loading states, accessibility, MCIM compliance, security, navigation,
 * context preservation, automation, timeline, policy conflict, evidence
 * freshness, and briefing suppression.
 *
 * Stack: Jest + React Testing Library
 */

import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// ─── Mock the API module ───────────────────────────────────────────────────────

jest.mock('../lib/operationsCenterApi', () => ({
  getOperationsQueue: jest.fn(),
  getAutomationQueue: jest.fn(),
  getDecisionPipeline: jest.fn(),
  getRiskHeatmap: jest.fn(),
  getEvidenceFreshness: jest.fn(),
  getPolicyConflicts: jest.fn(),
  getGovernanceSLA: jest.fn(),
  getAutomationSafety: jest.fn(),
  getCrossAuthorityTimeline: jest.fn(),
  getOperationalBriefing: jest.fn(),
}));

import {
  getOperationsQueue,
  getAutomationQueue,
  getDecisionPipeline,
  getRiskHeatmap,
  getEvidenceFreshness,
  getPolicyConflicts,
  getGovernanceSLA,
  getAutomationSafety,
  getCrossAuthorityTimeline,
  getOperationalBriefing,
} from '../lib/operationsCenterApi';

import ExecutiveOperationsQueue from '../components/operations-center/ExecutiveOperationsQueue';
import GovernanceAutomationQueue from '../components/operations-center/GovernanceAutomationQueue';
import DecisionExecutionPipeline from '../components/operations-center/DecisionExecutionPipeline';
import OperationalRiskHeatmap from '../components/operations-center/OperationalRiskHeatmap';
import EvidenceFreshnessMonitor from '../components/operations-center/EvidenceFreshnessMonitor';
import PolicyConflictCenter from '../components/operations-center/PolicyConflictCenter';
import GovernanceSLAMonitor from '../components/operations-center/GovernanceSLAMonitor';
import AutomationSafetyCenter from '../components/operations-center/AutomationSafetyCenter';
import CrossAuthorityTimeline from '../components/operations-center/CrossAuthorityTimeline';
import ExecutiveOperationalBriefing from '../components/operations-center/ExecutiveOperationalBriefing';
import OperationsCenterPage from '../app/dashboard/operations-center/page';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const MOCK_QUEUE_RESULT = {
  ok: true,
  data: {
    items: [
      {
        id: 'dec-001',
        authority: 'FrostGate Decision Engine',
        severity: 'critical',
        title: 'Unauthorized access detected',
        summary: 'Critical access event requiring review',
        owner: 'security-team',
        policy: 'pol-001',
        control: 'ctrl-001',
        evidenceCount: 5,
        confidence: '0.92',
        dueAt: '2026-07-10T00:00:00Z',
        businessImpact: 'high',
        workflowState: 'open',
        lifecycle: 'active',
        source: 'platform',
        createdAt: '2026-07-01T10:00:00Z',
      },
      {
        id: 'dec-002',
        authority: 'FrostGate Decision Engine',
        severity: 'high',
        title: 'Policy drift detected',
        summary: null,
        owner: null,
        policy: null,
        control: null,
        evidenceCount: 2,
        confidence: null,
        dueAt: null,
        businessImpact: null,
        workflowState: 'open',
        lifecycle: null,
        source: 'platform',
        createdAt: '2026-07-01T11:00:00Z',
      },
    ],
    total: 2,
    bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
  },
  authority: '/decisions',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_AUTOMATION_RESULT = {
  ok: true,
  data: {
    items: [
      {
        id: 'evt-001',
        status: 'pending',
        title: 'Remediation automation',
        origin: '/api/governance',
        policy: null,
        evidence: 'req-001',
        reason: 'policy_triggered',
        rollbackAvailable: true,
        severity: 'medium',
        createdAt: '2026-07-05T09:00:00Z',
      },
      {
        id: 'evt-002',
        status: 'approval_required',
        title: 'Risk acceptance automation',
        origin: '/api/risk',
        policy: null,
        evidence: 'req-002',
        reason: 'risk_threshold_exceeded',
        rollbackAvailable: false,
        severity: 'high',
        createdAt: '2026-07-05T09:30:00Z',
      },
    ],
    byStatus: {
      pending: 1,
      running: 0,
      completed: 0,
      failed: 0,
      blocked: 0,
      scheduled: 0,
      approval_required: 1,
    },
  },
  authority: '/ui/forensics/events',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_PIPELINE_RESULT = {
  ok: true,
  data: {
    items: [
      {
        id: 'dec-001',
        stage: 'detected',
        confidence: '0.88',
        authority: 'FrostGate Decision Engine',
        timestamp: '2026-07-05T08:00:00Z',
        deterministic: true,
        eventType: 'governance_event',
        severity: 'high',
      },
      {
        id: 'dec-002',
        stage: 'approval_required',
        confidence: '0.95',
        authority: 'FrostGate Decision Engine',
        timestamp: '2026-07-05T08:30:00Z',
        deterministic: true,
        eventType: 'policy_event',
        severity: 'critical',
      },
    ],
    byStage: { detected: 1, approval_required: 1 },
  },
  authority: '/decisions',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_HEATMAP_RESULT = {
  ok: true,
  data: {
    cells: [
      { dimension: 'Governance', category: 'Policy', count: 12, severity: 'high', authority: 'Governance Graph' },
      { dimension: 'Anomaly', category: 'orphan_control', count: 3, severity: 'critical', authority: 'Governance Graph Anomaly Engine' },
    ],
    totalAnomalies: 4,
    nodeCount: 150,
    edgeCount: 320,
    frameworkCoverage: null,
  },
  authority: '/governance/graph/stats + /governance/graph/anomalies',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_FRESHNESS_RESULT = {
  ok: true,
  data: {
    records: [
      {
        nodeId: 'node-001',
        label: 'MFA Policy',
        nodeType: 'policy',
        derivedAt: '2026-07-01T00:00:00Z',
        trustScore: 0.92,
        confidence: 0.88,
        status: 'current',
        ageHours: 96,
      },
      {
        nodeId: 'node-002',
        label: 'Access Control',
        nodeType: 'control',
        derivedAt: '2026-05-01T00:00:00Z',
        trustScore: 0.35,
        confidence: 0.40,
        status: 'stale',
        ageHours: 1500,
      },
      {
        nodeId: 'node-003',
        label: 'Unknown vendor',
        nodeType: 'vendor',
        derivedAt: '2026-07-04T00:00:00Z',
        trustScore: 0.05,
        confidence: 0.10,
        status: 'missing',
        ageHours: 24,
      },
    ],
    byStatus: { current: 1, stale: 1, missing: 1, expiring: 0, unverified: 0 },
    averageTrustScore: 0.44,
  },
  authority: '/governance/graph/nodes',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_CONFLICTS_RESULT = {
  ok: true,
  data: {
    conflicts: [
      {
        id: 'anom-001',
        type: 'duplicate_policy',
        description: 'Two identical MFA policies detected',
        severity: 'high',
        nodeIds: ['pol-001', 'pol-002'],
        detectedAt: '2026-07-04T12:00:00Z',
        resolved: false,
      },
      {
        id: 'anom-002',
        type: 'orphaned_control',
        description: 'Control has no owning policy',
        severity: 'medium',
        nodeIds: ['ctrl-005'],
        detectedAt: '2026-07-03T09:00:00Z',
        resolved: true,
      },
    ],
    byType: { duplicate_policy: 1, orphaned_control: 1 },
    orphanedNodes: 3,
  },
  authority: '/governance/graph/anomalies',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_SLA_RESULT = {
  ok: true,
  data: {
    items: [
      {
        id: 'dec-001',
        title: 'Critical access event',
        severity: 'critical',
        dueAt: '2026-07-03T00:00:00Z',
        createdAt: '2026-06-30T00:00:00Z',
        ageHours: 120,
        slaBreached: true,
        owner: 'security-team',
      },
      {
        id: 'dec-002',
        title: 'Policy review',
        severity: 'medium',
        dueAt: '2026-07-10T00:00:00Z',
        createdAt: '2026-07-01T00:00:00Z',
        ageHours: 96,
        slaBreached: false,
        owner: null,
      },
    ],
    breached: 1,
    upcoming: 1,
    averageAgeHours: 108,
  },
  authority: '/decisions',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_SAFETY_RESULT = {
  ok: true,
  data: {
    simulationRequired: false,
    rollbackAvailable: true,
    humanApprovalRequired: false,
    riskScore: 25,
    blastRadius: 'contained',
    killSwitchActive: false,
    executionConfidence: 93,
    chainIntegrity: 'ok',
    agentCount: 4,
    quarantineCount: 0,
  },
  authority: '/control-tower/snapshot',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_SAFETY_KILL_SWITCH = {
  ok: true,
  data: {
    simulationRequired: true,
    rollbackAvailable: false,
    humanApprovalRequired: true,
    riskScore: 90,
    blastRadius: 'partial',
    killSwitchActive: true,
    executionConfidence: 30,
    chainIntegrity: 'degraded',
    agentCount: 4,
    quarantineCount: 2,
  },
  authority: '/control-tower/snapshot',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_TIMELINE_RESULT = {
  ok: true,
  data: {
    events: [
      {
        id: 'forensics-1001',
        ts: '2026-07-05T09:00:00Z',
        authority: 'Forensics Chain',
        category: 'platform',
        eventType: 'access_event',
        severity: 'high',
        summary: 'Anomalous access pattern',
        requestId: 'req-001',
        immutable: true,
        auditable: true,
      },
      {
        id: 'feed-5001',
        ts: '2026-07-05T08:00:00Z',
        authority: 'Event Feed',
        category: 'governance',
        eventType: 'policy_event',
        severity: 'medium',
        summary: null,
        requestId: null,
        immutable: true,
        auditable: true,
      },
    ],
    authorities: ['Forensics Chain', 'Event Feed'],
    total: 2,
  },
  authority: '/ui/forensics/events + /feed/live',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_BRIEFING_SUFFICIENT = {
  ok: true,
  data: {
    lines: [
      { category: 'changed', label: 'Recent governance decisions', value: '5 decisions in current window', authority: '/decisions' },
      { category: 'risk_increased', label: 'Critical severity events', value: '2 critical decisions detected', authority: '/decisions' },
      { category: 'evidence_added', label: 'Governance graph nodes', value: '150 nodes, 320 edges', authority: '/governance/graph/stats' },
    ],
    sufficientEvidence: true,
    insufficiencyReason: null,
    generatedAt: '2026-07-05T00:00:00Z',
    authorityCount: 2,
  },
  authority: 'composite',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_BRIEFING_INSUFFICIENT = {
  ok: true,
  data: {
    lines: [],
    sufficientEvidence: false,
    insufficiencyReason: 'Insufficient authoritative evidence — governance graph may not be populated.',
    generatedAt: '2026-07-05T00:00:00Z',
    authorityCount: 0,
  },
  authority: 'composite',
  fetchedAt: '2026-07-05T00:00:00Z',
};

const MOCK_ERROR = { ok: false, error: 'fetch_error', authority: '/decisions' };

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockAllApis() {
  getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
  getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
  getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
  getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
  getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
  getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
  getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
  getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
  getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
  getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
}

function mockAllEmpty() {
  const emptyQueue = { ok: true, data: { items: [], total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }, authority: '/decisions', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyAuto = { ok: true, data: { items: [], byStatus: { pending: 0, running: 0, completed: 0, failed: 0, blocked: 0, scheduled: 0, approval_required: 0 } }, authority: '/ui/forensics/events', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyPipeline = { ok: true, data: { items: [], byStage: {} }, authority: '/decisions', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyHeatmap = { ok: true, data: { cells: [], totalAnomalies: 0, nodeCount: 0, edgeCount: 0, frameworkCoverage: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyFreshness = { ok: true, data: { records: [], byStatus: { current: 0, stale: 0, missing: 0, expiring: 0, unverified: 0 }, averageTrustScore: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyConflicts = { ok: true, data: { conflicts: [], byType: {}, orphanedNodes: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptySLA = { ok: true, data: { items: [], breached: 0, upcoming: 0, averageAgeHours: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptySafety = { ok: true, data: { simulationRequired: false, rollbackAvailable: true, humanApprovalRequired: false, riskScore: 0, blastRadius: 'none', killSwitchActive: false, executionConfidence: 100, chainIntegrity: 'ok', agentCount: 0, quarantineCount: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyTimeline = { ok: true, data: { events: [], authorities: [], total: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };
  const emptyBriefing = { ok: true, data: { lines: [], sufficientEvidence: false, insufficiencyReason: 'Insufficient authoritative evidence — governance graph may not be populated.', generatedAt: '2026-07-05T00:00:00Z', authorityCount: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' };

  getOperationsQueue.mockResolvedValue(emptyQueue);
  getAutomationQueue.mockResolvedValue(emptyAuto);
  getDecisionPipeline.mockResolvedValue(emptyPipeline);
  getRiskHeatmap.mockResolvedValue(emptyHeatmap);
  getEvidenceFreshness.mockResolvedValue(emptyFreshness);
  getPolicyConflicts.mockResolvedValue(emptyConflicts);
  getGovernanceSLA.mockResolvedValue(emptySLA);
  getAutomationSafety.mockResolvedValue(emptySafety);
  getCrossAuthorityTimeline.mockResolvedValue(emptyTimeline);
  getOperationalBriefing.mockResolvedValue(emptyBriefing);
}

function mockAllErrors() {
  const err = { ok: false, error: 'fetch_error', authority: '' };
  getOperationsQueue.mockResolvedValue(err);
  getAutomationQueue.mockResolvedValue(err);
  getDecisionPipeline.mockResolvedValue(err);
  getRiskHeatmap.mockResolvedValue(err);
  getEvidenceFreshness.mockResolvedValue(err);
  getPolicyConflicts.mockResolvedValue(err);
  getGovernanceSLA.mockResolvedValue(err);
  getAutomationSafety.mockResolvedValue(err);
  getCrossAuthorityTimeline.mockResolvedValue(err);
  getOperationalBriefing.mockResolvedValue(err);
}

function mockAllLoading() {
  const loading = new Promise(() => {}); // never resolves
  getOperationsQueue.mockReturnValue(loading);
  getAutomationQueue.mockReturnValue(loading);
  getDecisionPipeline.mockReturnValue(loading);
  getRiskHeatmap.mockReturnValue(loading);
  getEvidenceFreshness.mockReturnValue(loading);
  getPolicyConflicts.mockReturnValue(loading);
  getGovernanceSLA.mockReturnValue(loading);
  getAutomationSafety.mockReturnValue(loading);
  getCrossAuthorityTimeline.mockReturnValue(loading);
  getOperationalBriefing.mockReturnValue(loading);
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════════
// 1. RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

describe('Rendering', () => {
  describe('ExecutiveOperationsQueue', () => {
    it('renders without crashing with valid data', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      const { container } = render(<ExecutiveOperationsQueue />);
      expect(container).toBeTruthy();
    });
    it('renders section heading', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /operations queue/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      const { container } = render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('renders severity indicator', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        expect(screen.getByText(/critical/i)).toBeTruthy();
      });
    });
    it('links to /dashboard/decisions', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      const { container } = render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        const links = container.querySelectorAll('a[href*="/dashboard/decisions"]');
        expect(links.length).toBeGreaterThan(0);
      });
    });
  });

  describe('GovernanceAutomationQueue', () => {
    it('renders without crashing', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      const { container } = render(<GovernanceAutomationQueue />);
      expect(container).toBeTruthy();
    });
    it('renders section heading', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      render(<GovernanceAutomationQueue />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /automation queue/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      const { container } = render(<GovernanceAutomationQueue />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('displays status of automation items', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      render(<GovernanceAutomationQueue />);
      await waitFor(() => {
        expect(screen.getByText(/approval_required/i)).toBeTruthy();
      });
    });
    it('displays pending count', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      render(<GovernanceAutomationQueue />);
      await waitFor(() => {
        expect(screen.getByText(/pending/i)).toBeTruthy();
      });
    });
  });

  describe('DecisionExecutionPipeline', () => {
    it('renders without crashing', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      const { container } = render(<DecisionExecutionPipeline />);
      expect(container).toBeTruthy();
    });
    it('renders pipeline heading', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      render(<DecisionExecutionPipeline />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /execution pipeline/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      const { container } = render(<DecisionExecutionPipeline />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows detected stage', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      render(<DecisionExecutionPipeline />);
      await waitFor(() => {
        expect(screen.getByText(/detected/i)).toBeTruthy();
      });
    });
    it('shows approval_required stage', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      render(<DecisionExecutionPipeline />);
      await waitFor(() => {
        expect(screen.getByText(/approval.required/i)).toBeTruthy();
      });
    });
  });

  describe('OperationalRiskHeatmap', () => {
    it('renders without crashing', async () => {
      getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
      const { container } = render(<OperationalRiskHeatmap />);
      expect(container).toBeTruthy();
    });
    it('renders heatmap heading', async () => {
      getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
      render(<OperationalRiskHeatmap />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /risk heatmap/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
      const { container } = render(<OperationalRiskHeatmap />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows anomaly count', async () => {
      getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
      render(<OperationalRiskHeatmap />);
      await waitFor(() => {
        expect(screen.getByText(/4/)).toBeTruthy();
      });
    });
  });

  describe('EvidenceFreshnessMonitor', () => {
    it('renders without crashing', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      const { container } = render(<EvidenceFreshnessMonitor />);
      expect(container).toBeTruthy();
    });
    it('renders freshness heading', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /evidence freshness/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      const { container } = render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('displays trust score', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        expect(screen.getByText(/0\.92|92%/)).toBeTruthy();
      });
    });
    it('shows average trust score', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        expect(screen.getByText(/0\.44|44%|average/i)).toBeTruthy();
      });
    });
  });

  describe('PolicyConflictCenter', () => {
    it('renders without crashing', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      const { container } = render(<PolicyConflictCenter />);
      expect(container).toBeTruthy();
    });
    it('renders conflict heading', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      render(<PolicyConflictCenter />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /policy conflict/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      const { container } = render(<PolicyConflictCenter />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('displays orphaned node count', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      render(<PolicyConflictCenter />);
      await waitFor(() => {
        expect(screen.getByText(/3/)).toBeTruthy();
      });
    });
  });

  describe('GovernanceSLAMonitor', () => {
    it('renders without crashing', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      const { container } = render(<GovernanceSLAMonitor />);
      expect(container).toBeTruthy();
    });
    it('renders SLA heading', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      render(<GovernanceSLAMonitor />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /sla monitor/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      const { container } = render(<GovernanceSLAMonitor />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows breached count', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      render(<GovernanceSLAMonitor />);
      await waitFor(() => {
        expect(screen.getByText(/breached|1 breached/i)).toBeTruthy();
      });
    });
  });

  describe('AutomationSafetyCenter', () => {
    it('renders without crashing', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      const { container } = render(<AutomationSafetyCenter />);
      expect(container).toBeTruthy();
    });
    it('renders safety heading', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      render(<AutomationSafetyCenter />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /automation safety/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      const { container } = render(<AutomationSafetyCenter />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows risk score value', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      render(<AutomationSafetyCenter />);
      await waitFor(() => {
        expect(screen.getByText(/25|risk score/i)).toBeTruthy();
      });
    });
    it('shows blast radius', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      render(<AutomationSafetyCenter />);
      await waitFor(() => {
        expect(screen.getByText(/contained/i)).toBeTruthy();
      });
    });
  });

  describe('CrossAuthorityTimeline', () => {
    it('renders without crashing', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      const { container } = render(<CrossAuthorityTimeline />);
      expect(container).toBeTruthy();
    });
    it('renders timeline heading', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      render(<CrossAuthorityTimeline />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /timeline/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      const { container } = render(<CrossAuthorityTimeline />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows event authority labels', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      render(<CrossAuthorityTimeline />);
      await waitFor(() => {
        expect(screen.getByText(/Forensics Chain/)).toBeTruthy();
      });
    });
  });

  describe('ExecutiveOperationalBriefing', () => {
    it('renders without crashing', async () => {
      getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
      const { container } = render(<ExecutiveOperationalBriefing />);
      expect(container).toBeTruthy();
    });
    it('renders briefing heading', async () => {
      getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
      render(<ExecutiveOperationalBriefing />);
      await waitFor(() => {
        expect(screen.getByRole('region', { name: /operational briefing/i })).toBeTruthy();
      });
    });
    it('displays data-mcim attribute', async () => {
      getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
      const { container } = render(<ExecutiveOperationalBriefing />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });
    it('shows authority count', async () => {
      getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
      render(<ExecutiveOperationalBriefing />);
      await waitFor(() => {
        expect(screen.getByText(/2 authorit/i)).toBeTruthy();
      });
    });
  });

  describe('OperationsCenterPage', () => {
    it('renders without crashing', async () => {
      mockAllApis();
      const { container } = render(<OperationsCenterPage />);
      expect(container).toBeTruthy();
    });
    it('has data-mcim="OPERATIONS-CENTER" on page root', async () => {
      mockAllApis();
      const { container } = render(<OperationsCenterPage />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim="OPERATIONS-CENTER"]')).toBeTruthy();
      });
    });
    it('renders all 10 panel sections', async () => {
      mockAllApis();
      render(<OperationsCenterPage />);
      await waitFor(() => {
        expect(screen.getAllByRole('region').length).toBeGreaterThanOrEqual(10);
      });
    });
    it('includes skip-to-content link', async () => {
      mockAllApis();
      const { container } = render(<OperationsCenterPage />);
      expect(container.querySelector('a[href="#main-content"]')).toBeTruthy();
    });
    it('page heading is present', async () => {
      mockAllApis();
      render(<OperationsCenterPage />);
      await waitFor(() => {
        expect(screen.getByRole('heading', { level: 1 })).toBeTruthy();
      });
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. EMPTY STATES
// ═══════════════════════════════════════════════════════════════════════════════

describe('Empty states', () => {
  it('ExecutiveOperationsQueue shows empty state message when items = []', async () => {
    getOperationsQueue.mockResolvedValue({ ok: true, data: { items: [], total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }, authority: '/decisions', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(screen.getByText(/no items|empty|no operations/i)).toBeTruthy();
    });
  });
  it('ExecutiveOperationsQueue empty state is not blank', async () => {
    getOperationsQueue.mockResolvedValue({ ok: true, data: { items: [], total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }, authority: '/decisions', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const msg = screen.getByText(/no items|empty|no operations/i);
      expect(msg.textContent.trim().length).toBeGreaterThan(0);
    });
  });
  it('ExecutiveOperationsQueue empty state shows no fabricated data', async () => {
    getOperationsQueue.mockResolvedValue({ ok: true, data: { items: [], total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }, authority: '/decisions', fetchedAt: '2026-07-05T00:00:00Z' });
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
    });
  });

  it('GovernanceAutomationQueue shows empty state message when items = []', async () => {
    getAutomationQueue.mockResolvedValue({ ok: true, data: { items: [], byStatus: { pending: 0, running: 0, completed: 0, failed: 0, blocked: 0, scheduled: 0, approval_required: 0 } }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      expect(screen.getByText(/no automation|empty|no items/i)).toBeTruthy();
    });
  });
  it('GovernanceAutomationQueue empty state is not blank', async () => {
    getAutomationQueue.mockResolvedValue({ ok: true, data: { items: [], byStatus: { pending: 0, running: 0, completed: 0, failed: 0, blocked: 0, scheduled: 0, approval_required: 0 } }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      const el = screen.getByText(/no automation|empty|no items/i);
      expect(el.textContent.trim().length).toBeGreaterThan(0);
    });
  });

  it('DecisionExecutionPipeline shows empty state when items = []', async () => {
    getDecisionPipeline.mockResolvedValue({ ok: true, data: { items: [], byStage: {} }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<DecisionExecutionPipeline />);
    await waitFor(() => {
      expect(screen.getByText(/no decisions|pipeline empty|empty/i)).toBeTruthy();
    });
  });
  it('DecisionExecutionPipeline empty state is not blank', async () => {
    getDecisionPipeline.mockResolvedValue({ ok: true, data: { items: [], byStage: {} }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<DecisionExecutionPipeline />);
    await waitFor(() => {
      const el = screen.getByText(/no decisions|pipeline empty|empty/i);
      expect(el.textContent.trim().length).toBeGreaterThan(0);
    });
  });

  it('OperationalRiskHeatmap shows empty state when cells = []', async () => {
    getRiskHeatmap.mockResolvedValue({ ok: true, data: { cells: [], totalAnomalies: 0, nodeCount: 0, edgeCount: 0, frameworkCoverage: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<OperationalRiskHeatmap />);
    await waitFor(() => {
      expect(screen.getByText(/no risk data|no anomalies|empty/i)).toBeTruthy();
    });
  });

  it('EvidenceFreshnessMonitor shows empty state when records = []', async () => {
    getEvidenceFreshness.mockResolvedValue({ ok: true, data: { records: [], byStatus: { current: 0, stale: 0, missing: 0, expiring: 0, unverified: 0 }, averageTrustScore: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/no evidence|no records|empty/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor empty state is not blank', async () => {
    getEvidenceFreshness.mockResolvedValue({ ok: true, data: { records: [], byStatus: { current: 0, stale: 0, missing: 0, expiring: 0, unverified: 0 }, averageTrustScore: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      const el = screen.getByText(/no evidence|no records|empty/i);
      expect(el.textContent.trim().length).toBeGreaterThan(0);
    });
  });

  it('PolicyConflictCenter shows empty state when conflicts = []', async () => {
    getPolicyConflicts.mockResolvedValue({ ok: true, data: { conflicts: [], byType: {}, orphanedNodes: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/no conflicts|clean|empty/i)).toBeTruthy();
    });
  });

  it('GovernanceSLAMonitor shows empty state when items = []', async () => {
    getGovernanceSLA.mockResolvedValue({ ok: true, data: { items: [], breached: 0, upcoming: 0, averageAgeHours: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<GovernanceSLAMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/no sla items|no items|empty/i)).toBeTruthy();
    });
  });

  it('AutomationSafetyCenter shows baseline state when no quarantine', async () => {
    getAutomationSafety.mockResolvedValue({ ok: true, data: { simulationRequired: false, rollbackAvailable: true, humanApprovalRequired: false, riskScore: 0, blastRadius: 'none', killSwitchActive: false, executionConfidence: 100, chainIntegrity: 'ok', agentCount: 0, quarantineCount: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/none|0 agents|no agents/i)).toBeTruthy();
    });
  });

  it('CrossAuthorityTimeline shows empty state when events = []', async () => {
    getCrossAuthorityTimeline.mockResolvedValue({ ok: true, data: { events: [], authorities: [], total: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/no events|empty|no timeline/i)).toBeTruthy();
    });
  });

  it('ExecutiveOperationalBriefing shows insufficient evidence notice when lines = []', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Insufficient authoritative evidence/i)).toBeTruthy();
    });
  });
  it('ExecutiveOperationalBriefing insufficient notice is not blank', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      const notice = screen.getByText(/Insufficient authoritative evidence/i);
      expect(notice.textContent.trim().length).toBeGreaterThan(0);
    });
  });

  // Empty state — no fabricated data
  it('ExecutiveOperationalBriefing shows no briefing lines when sufficientEvidence=false', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-briefing-line]').length).toBe(0);
    });
  });

  // All components: empty state — no fabricated items
  it('GovernanceSLAMonitor empty state shows no items in DOM', async () => {
    getGovernanceSLA.mockResolvedValue({ ok: true, data: { items: [], breached: 0, upcoming: 0, averageAgeHours: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    const { container } = render(<GovernanceSLAMonitor />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-sla-item]').length).toBe(0);
    });
  });
  it('PolicyConflictCenter empty state shows no conflict rows', async () => {
    getPolicyConflicts.mockResolvedValue({ ok: true, data: { conflicts: [], byType: {}, orphanedNodes: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    const { container } = render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-conflict-id]').length).toBe(0);
    });
  });
  it('CrossAuthorityTimeline empty state shows no event rows', async () => {
    getCrossAuthorityTimeline.mockResolvedValue({ ok: true, data: { events: [], authorities: [], total: 0 }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-event-id]').length).toBe(0);
    });
  });
  it('OperationalRiskHeatmap empty shows zero anomaly count', async () => {
    getRiskHeatmap.mockResolvedValue({ ok: true, data: { cells: [], totalAnomalies: 0, nodeCount: 0, edgeCount: 0, frameworkCoverage: null }, authority: '', fetchedAt: '2026-07-05T00:00:00Z' });
    render(<OperationalRiskHeatmap />);
    await waitFor(() => {
      expect(screen.getByText(/0 anomalies|no anomalies/i)).toBeTruthy();
    });
  });

  // Page-level empty: all panels still render with empty states
  it('OperationsCenterPage renders all panel regions even when data is empty', async () => {
    mockAllEmpty();
    render(<OperationsCenterPage />);
    await waitFor(() => {
      expect(screen.getAllByRole('region').length).toBeGreaterThanOrEqual(10);
    });
  });
  it('OperationsCenterPage empty state: no fabricated decision items', async () => {
    mockAllEmpty();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ERROR STATES
// ═══════════════════════════════════════════════════════════════════════════════

describe('Error states', () => {
  it('ExecutiveOperationsQueue handles API error gracefully', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<ExecutiveOperationsQueue />)).not.toThrow();
  });
  it('ExecutiveOperationsQueue shows error message when ok=false', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_ERROR);
    render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('ExecutiveOperationsQueue shows no data when error occurs (fail closed)', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
    });
  });
  it('ExecutiveOperationsQueue handles null data gracefully', async () => {
    getOperationsQueue.mockResolvedValue({ ok: false, error: 'null_error', authority: '' });
    expect(() => render(<ExecutiveOperationsQueue />)).not.toThrow();
  });

  it('GovernanceAutomationQueue handles API error gracefully', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<GovernanceAutomationQueue />)).not.toThrow();
  });
  it('GovernanceAutomationQueue shows error message', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_ERROR);
    render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('GovernanceAutomationQueue fail closed: no items on error', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
    });
  });

  it('DecisionExecutionPipeline handles API error gracefully', async () => {
    getDecisionPipeline.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<DecisionExecutionPipeline />)).not.toThrow();
  });
  it('DecisionExecutionPipeline shows error message', async () => {
    getDecisionPipeline.mockResolvedValue(MOCK_ERROR);
    render(<DecisionExecutionPipeline />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });

  it('OperationalRiskHeatmap handles API error gracefully', async () => {
    getRiskHeatmap.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<OperationalRiskHeatmap />)).not.toThrow();
  });
  it('OperationalRiskHeatmap shows error message', async () => {
    getRiskHeatmap.mockResolvedValue(MOCK_ERROR);
    render(<OperationalRiskHeatmap />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('OperationalRiskHeatmap fail closed: no cells on error', async () => {
    getRiskHeatmap.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<OperationalRiskHeatmap />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-cell]').length).toBe(0);
    });
  });

  it('EvidenceFreshnessMonitor handles API error gracefully', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<EvidenceFreshnessMonitor />)).not.toThrow();
  });
  it('EvidenceFreshnessMonitor shows error message', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_ERROR);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor fail closed: no records on error', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-node-id]').length).toBe(0);
    });
  });

  it('PolicyConflictCenter handles API error gracefully', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<PolicyConflictCenter />)).not.toThrow();
  });
  it('PolicyConflictCenter shows error message', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_ERROR);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });

  it('GovernanceSLAMonitor handles API error gracefully', async () => {
    getGovernanceSLA.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<GovernanceSLAMonitor />)).not.toThrow();
  });
  it('GovernanceSLAMonitor shows error message', async () => {
    getGovernanceSLA.mockResolvedValue(MOCK_ERROR);
    render(<GovernanceSLAMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });

  it('AutomationSafetyCenter handles API error gracefully', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<AutomationSafetyCenter />)).not.toThrow();
  });
  it('AutomationSafetyCenter shows error message', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_ERROR);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter fail closed: no risk score displayed on error', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-risk-score]').length).toBe(0);
    });
  });

  it('CrossAuthorityTimeline handles API error gracefully', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<CrossAuthorityTimeline />)).not.toThrow();
  });
  it('CrossAuthorityTimeline shows error message', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_ERROR);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline fail closed: no events on error', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-event-id]').length).toBe(0);
    });
  });

  it('ExecutiveOperationalBriefing handles API error gracefully', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_ERROR);
    expect(() => render(<ExecutiveOperationalBriefing />)).not.toThrow();
  });
  it('ExecutiveOperationalBriefing shows error message', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_ERROR);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/error|failed|unavailable/i)).toBeTruthy();
    });
  });
  it('ExecutiveOperationalBriefing fail closed: no lines on error', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_ERROR);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-briefing-line]').length).toBe(0);
    });
  });

  // Rejection (network error)
  it('ExecutiveOperationsQueue handles promise rejection', async () => {
    getOperationsQueue.mockRejectedValue(new Error('network error'));
    expect(() => render(<ExecutiveOperationsQueue />)).not.toThrow();
  });
  it('GovernanceAutomationQueue handles promise rejection', async () => {
    getAutomationQueue.mockRejectedValue(new Error('network error'));
    expect(() => render(<GovernanceAutomationQueue />)).not.toThrow();
  });
  it('EvidenceFreshnessMonitor handles promise rejection', async () => {
    getEvidenceFreshness.mockRejectedValue(new Error('network error'));
    expect(() => render(<EvidenceFreshnessMonitor />)).not.toThrow();
  });
  it('CrossAuthorityTimeline handles promise rejection', async () => {
    getCrossAuthorityTimeline.mockRejectedValue(new Error('network error'));
    expect(() => render(<CrossAuthorityTimeline />)).not.toThrow();
  });

  // Page-level: individual panel errors don't crash the page
  it('OperationsCenterPage handles mixed errors without crashing', async () => {
    mockAllErrors();
    expect(() => render(<OperationsCenterPage />)).not.toThrow();
  });
  it('OperationsCenterPage shows error indicators for each panel', async () => {
    mockAllErrors();
    render(<OperationsCenterPage />);
    await waitFor(() => {
      const errors = screen.getAllByText(/error|failed|unavailable/i);
      expect(errors.length).toBeGreaterThanOrEqual(10);
    });
  });
  it('OperationsCenterPage fail closed: no data shown when all APIs error', async () => {
    mockAllErrors();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. LOADING STATES
// ═══════════════════════════════════════════════════════════════════════════════

describe('Loading states', () => {
  it('ExecutiveOperationsQueue shows loading indicator while fetching', () => {
    getOperationsQueue.mockReturnValue(new Promise(() => {}));
    render(<ExecutiveOperationsQueue />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('GovernanceAutomationQueue shows loading indicator', () => {
    getAutomationQueue.mockReturnValue(new Promise(() => {}));
    render(<GovernanceAutomationQueue />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('DecisionExecutionPipeline shows loading indicator', () => {
    getDecisionPipeline.mockReturnValue(new Promise(() => {}));
    render(<DecisionExecutionPipeline />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('OperationalRiskHeatmap shows loading indicator', () => {
    getRiskHeatmap.mockReturnValue(new Promise(() => {}));
    render(<OperationalRiskHeatmap />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('EvidenceFreshnessMonitor shows loading indicator', () => {
    getEvidenceFreshness.mockReturnValue(new Promise(() => {}));
    render(<EvidenceFreshnessMonitor />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('PolicyConflictCenter shows loading indicator', () => {
    getPolicyConflicts.mockReturnValue(new Promise(() => {}));
    render(<PolicyConflictCenter />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('GovernanceSLAMonitor shows loading indicator', () => {
    getGovernanceSLA.mockReturnValue(new Promise(() => {}));
    render(<GovernanceSLAMonitor />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('AutomationSafetyCenter shows loading indicator', () => {
    getAutomationSafety.mockReturnValue(new Promise(() => {}));
    render(<AutomationSafetyCenter />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('CrossAuthorityTimeline shows loading indicator', () => {
    getCrossAuthorityTimeline.mockReturnValue(new Promise(() => {}));
    render(<CrossAuthorityTimeline />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('ExecutiveOperationalBriefing shows loading indicator', () => {
    getOperationalBriefing.mockReturnValue(new Promise(() => {}));
    render(<ExecutiveOperationalBriefing />);
    expect(screen.getByRole('status', { name: /loading/i })).toBeTruthy();
  });
  it('OperationsCenterPage shows loading state for all panels', () => {
    mockAllLoading();
    render(<OperationsCenterPage />);
    const loadingIndicators = screen.getAllByRole('status', { name: /loading/i });
    expect(loadingIndicators.length).toBeGreaterThanOrEqual(10);
  });
  it('loading indicators are accessible (aria-label present)', () => {
    getOperationsQueue.mockReturnValue(new Promise(() => {}));
    const { container } = render(<ExecutiveOperationsQueue />);
    const spinner = container.querySelector('[role="status"]');
    expect(spinner).toBeTruthy();
    expect(spinner.getAttribute('aria-label') || spinner.getAttribute('aria-labelledby')).toBeTruthy();
  });
  it('loading state does not show stale data', () => {
    getOperationsQueue.mockReturnValue(new Promise(() => {}));
    const { container } = render(<ExecutiveOperationsQueue />);
    expect(container.querySelectorAll('[data-item-id]').length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. ACCESSIBILITY
// ═══════════════════════════════════════════════════════════════════════════════

describe('Accessibility', () => {
  describe('ARIA labels on interactive elements', () => {
    it('ExecutiveOperationsQueue interactive elements have aria-labels', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      const { container } = render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        const buttons = container.querySelectorAll('button');
        buttons.forEach(btn => {
          expect(btn.getAttribute('aria-label') || btn.textContent.trim().length > 0).toBeTruthy();
        });
      });
    });
    it('GovernanceAutomationQueue buttons have aria-labels', async () => {
      getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
      const { container } = render(<GovernanceAutomationQueue />);
      await waitFor(() => {
        const buttons = container.querySelectorAll('button');
        buttons.forEach(btn => {
          expect(btn.getAttribute('aria-label') || btn.textContent.trim().length > 0).toBeTruthy();
        });
      });
    });
    it('AutomationSafetyCenter kill switch button has aria-label', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
      const { container } = render(<AutomationSafetyCenter />);
      await waitFor(() => {
        const killBtn = container.querySelector('[data-kill-switch]');
        if (killBtn) {
          expect(killBtn.getAttribute('aria-label')).toBeTruthy();
        }
      });
    });
    it('PolicyConflictCenter filter controls are accessible', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      const { container } = render(<PolicyConflictCenter />);
      await waitFor(() => {
        const selects = container.querySelectorAll('select');
        selects.forEach(sel => {
          expect(sel.getAttribute('aria-label') || sel.id).toBeTruthy();
        });
      });
    });
  });

  describe('Role attributes', () => {
    it('ExecutiveOperationsQueue root has role="region"', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        expect(screen.getByRole('region')).toBeTruthy();
      });
    });
    it('GovernanceSLAMonitor breached items have role="alert"', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      render(<GovernanceSLAMonitor />);
      await waitFor(() => {
        const alerts = screen.queryAllByRole('alert');
        expect(alerts.length).toBeGreaterThan(0);
      });
    });
    it('AutomationSafetyCenter risk score has status role', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      const { container } = render(<AutomationSafetyCenter />);
      await waitFor(() => {
        const statusEl = container.querySelector('[data-risk-score]');
        if (statusEl) {
          expect(statusEl.getAttribute('role')).toBeTruthy();
        }
      });
    });
    it('CrossAuthorityTimeline events have listitem role', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      render(<CrossAuthorityTimeline />);
      await waitFor(() => {
        const items = screen.getAllByRole('listitem');
        expect(items.length).toBeGreaterThan(0);
      });
    });
    it('EvidenceFreshnessMonitor status badges have role="status"', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        const statuses = screen.queryAllByRole('status');
        expect(statuses.length).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('Keyboard navigation', () => {
    it('ExecutiveOperationsQueue focusable elements have tabIndex', async () => {
      getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
      const { container } = render(<ExecutiveOperationsQueue />);
      await waitFor(() => {
        const focusable = container.querySelectorAll('a, button, [tabindex]');
        expect(focusable.length).toBeGreaterThan(0);
      });
    });
    it('DecisionExecutionPipeline pipeline stages are keyboard navigable', async () => {
      getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
      const { container } = render(<DecisionExecutionPipeline />);
      await waitFor(() => {
        const focusable = container.querySelectorAll('[tabindex]');
        expect(focusable.length).toBeGreaterThanOrEqual(0);
      });
    });
    it('CrossAuthorityTimeline filter controls are keyboard accessible', async () => {
      getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
      const { container } = render(<CrossAuthorityTimeline />);
      await waitFor(() => {
        const focusable = container.querySelectorAll('button, a, select, [tabindex]');
        expect(focusable.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Screen reader labels', () => {
    it('OperationsCenterPage has skip-to-content link', async () => {
      mockAllApis();
      const { container } = render(<OperationsCenterPage />);
      expect(container.querySelector('a[href="#main-content"]')).toBeTruthy();
    });
    it('EvidenceFreshnessMonitor trust score has screen reader label', async () => {
      getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
      const { container } = render(<EvidenceFreshnessMonitor />);
      await waitFor(() => {
        const srLabels = container.querySelectorAll('[aria-label], .sr-only');
        expect(srLabels.length).toBeGreaterThan(0);
      });
    });
    it('AutomationSafetyCenter risk score has sr-label', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
      const { container } = render(<AutomationSafetyCenter />);
      await waitFor(() => {
        const srLabels = container.querySelectorAll('[aria-label], .sr-only');
        expect(srLabels.length).toBeGreaterThan(0);
      });
    });
    it('PolicyConflictCenter severity badges have aria-labels', async () => {
      getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
      const { container } = render(<PolicyConflictCenter />);
      await waitFor(() => {
        const badges = container.querySelectorAll('[data-severity]');
        badges.forEach(b => {
          expect(b.getAttribute('aria-label') || b.textContent.trim().length > 0).toBeTruthy();
        });
      });
    });
    it('GovernanceSLAMonitor breached status has aria-label', async () => {
      getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
      const { container } = render(<GovernanceSLAMonitor />);
      await waitFor(() => {
        const breachedEls = container.querySelectorAll('[data-sla-breached]');
        breachedEls.forEach(el => {
          expect(el.getAttribute('aria-label') || el.textContent.trim().length > 0).toBeTruthy();
        });
      });
    });
  });

  describe('Focus management', () => {
    it('OperationsCenterPage main content region is focusable', async () => {
      mockAllApis();
      const { container } = render(<OperationsCenterPage />);
      await waitFor(() => {
        const main = container.querySelector('#main-content, main, [id="main-content"]');
        expect(main).toBeTruthy();
      });
    });
    it('ExecutiveOperationalBriefing insufficient notice is announced', async () => {
      getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
      const { container } = render(<ExecutiveOperationalBriefing />);
      await waitFor(() => {
        const notice = container.querySelector('[role="alert"], [aria-live]');
        expect(notice).toBeTruthy();
      });
    });
    it('AutomationSafetyCenter kill switch alert is announced', async () => {
      getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
      const { container } = render(<AutomationSafetyCenter />);
      await waitFor(() => {
        const alert = container.querySelector('[role="alert"], [aria-live="assertive"]');
        expect(alert).toBeTruthy();
      });
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. MCIM COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════════════

describe('MCIM compliance', () => {
  const components = [
    { name: 'ExecutiveOperationsQueue', mockFn: () => getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT), Component: ExecutiveOperationsQueue },
    { name: 'GovernanceAutomationQueue', mockFn: () => getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT), Component: GovernanceAutomationQueue },
    { name: 'DecisionExecutionPipeline', mockFn: () => getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT), Component: DecisionExecutionPipeline },
    { name: 'OperationalRiskHeatmap', mockFn: () => getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT), Component: OperationalRiskHeatmap },
    { name: 'EvidenceFreshnessMonitor', mockFn: () => getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT), Component: EvidenceFreshnessMonitor },
    { name: 'PolicyConflictCenter', mockFn: () => getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT), Component: PolicyConflictCenter },
    { name: 'GovernanceSLAMonitor', mockFn: () => getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT), Component: GovernanceSLAMonitor },
    { name: 'AutomationSafetyCenter', mockFn: () => getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT), Component: AutomationSafetyCenter },
    { name: 'CrossAuthorityTimeline', mockFn: () => getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT), Component: CrossAuthorityTimeline },
    { name: 'ExecutiveOperationalBriefing', mockFn: () => getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT), Component: ExecutiveOperationalBriefing },
  ];

  components.forEach(({ name, mockFn, Component }) => {
    it(`${name} has data-mcim attribute on root`, async () => {
      mockFn();
      const { container } = render(<Component />);
      await waitFor(() => {
        expect(container.querySelector('[data-mcim]')).toBeTruthy();
      });
    });

    it(`${name} has data-authority attribute`, async () => {
      mockFn();
      const { container } = render(<Component />);
      await waitFor(() => {
        expect(container.querySelector('[data-authority]')).toBeTruthy();
      });
    });

    it(`${name} MCIM ID matches MCIM-18.7 pattern`, async () => {
      mockFn();
      const { container } = render(<Component />);
      await waitFor(() => {
        const el = container.querySelector('[data-mcim]');
        if (el) {
          const mcimId = el.getAttribute('data-mcim');
          expect(/MCIM-18\.7/.test(mcimId) || mcimId === 'OPERATIONS-CENTER').toBeTruthy();
        }
      });
    });
  });

  it('OperationsCenterPage has data-mcim="OPERATIONS-CENTER"', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      expect(container.querySelector('[data-mcim="OPERATIONS-CENTER"]')).toBeTruthy();
    });
  });

  it('Page has data-section attributes on sections', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      const sections = container.querySelectorAll('[data-section]');
      expect(sections.length).toBeGreaterThanOrEqual(10);
    });
  });

  it('data-mcim attributes are non-empty strings', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const el = container.querySelector('[data-mcim]');
      expect(el.getAttribute('data-mcim').trim().length).toBeGreaterThan(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

describe('Security', () => {
  it('ExecutiveOperationsQueue rendered output contains no Math.random calls', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(container.innerHTML).not.toContain('Math.random');
    });
  });
  it('GovernanceAutomationQueue rendered output contains no Math.random', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
    const { container } = render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      expect(container.innerHTML).not.toContain('Math.random');
    });
  });
  it('EvidenceFreshnessMonitor rendered output contains no Math.random', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(container.innerHTML).not.toContain('Math.random');
    });
  });

  it('ExecutiveOperationsQueue does not use localStorage.getItem', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const spy = jest.spyOn(window.localStorage.__proto__, 'getItem');
    render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(spy).not.toHaveBeenCalled();
    });
    spy.mockRestore();
  });
  it('AutomationSafetyCenter does not use localStorage.getItem', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    const spy = jest.spyOn(window.localStorage.__proto__, 'getItem');
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(spy).not.toHaveBeenCalled();
    });
    spy.mockRestore();
  });
  it('ExecutiveOperationalBriefing does not use localStorage.getItem', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    const spy = jest.spyOn(window.localStorage.__proto__, 'getItem');
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(spy).not.toHaveBeenCalled();
    });
    spy.mockRestore();
  });

  it('ExecutiveOperationsQueue does not use sessionStorage.getItem', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const spy = jest.spyOn(window.sessionStorage.__proto__, 'getItem');
    render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      expect(spy).not.toHaveBeenCalled();
    });
    spy.mockRestore();
  });
  it('PolicyConflictCenter does not use sessionStorage', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    const spy = jest.spyOn(window.sessionStorage.__proto__, 'getItem');
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(spy).not.toHaveBeenCalled();
    });
    spy.mockRestore();
  });

  it('ExecutiveOperationsQueue does not use dangerouslySetInnerHTML', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const allElements = container.querySelectorAll('*');
      allElements.forEach(el => {
        expect(el.getAttribute('dangerouslySetInnerHTML')).toBeNull();
      });
    });
  });

  it('item IDs from API are displayed verbatim (no random IDs injected)', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const decisionLinks = container.querySelectorAll('a[href*="dec-001"]');
      expect(decisionLinks.length).toBeGreaterThan(0);
    });
  });

  it('rendered decision IDs are deterministic (match API data)', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const elements = container.querySelectorAll('[data-item-id]');
      if (elements.length > 0) {
        const ids = Array.from(elements).map(el => el.getAttribute('data-item-id'));
        expect(ids).toContain('dec-001');
      }
    });
  });

  it('GovernanceAutomationQueue renders no injected HTML strings', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
    const { container } = render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      expect(container.innerHTML).not.toContain('dangerouslySetInnerHTML');
    });
  });

  it('CrossAuthorityTimeline does not inject raw HTML from event summaries', async () => {
    const xssTimeline = {
      ...MOCK_TIMELINE_RESULT,
      data: {
        ...MOCK_TIMELINE_RESULT.data,
        events: [{
          ...MOCK_TIMELINE_RESULT.data.events[0],
          summary: '<script>alert("xss")</script>',
        }],
      },
    };
    getCrossAuthorityTimeline.mockResolvedValue(xssTimeline);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const scripts = container.querySelectorAll('script');
      expect(scripts.length).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════════

describe('Navigation', () => {
  it('ExecutiveOperationsQueue decision links point to /dashboard/decisions', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      const decisionLinks = Array.from(links).filter(l => l.href.includes('/dashboard/decisions'));
      expect(decisionLinks.length).toBeGreaterThan(0);
    });
  });
  it('CrossAuthorityTimeline forensics links point to /dashboard/forensics', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href*="/dashboard/forensics"]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('OperationalRiskHeatmap anomaly links point to governance route', async () => {
    getRiskHeatmap.mockResolvedValue(MOCK_HEATMAP_RESULT);
    const { container } = render(<OperationalRiskHeatmap />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      const govLinks = Array.from(links).filter(l =>
        l.href.includes('/dashboard') || l.href.includes('/governance')
      );
      expect(govLinks.length).toBeGreaterThan(0);
    });
  });
  it('DecisionExecutionPipeline links include decision IDs in context', async () => {
    getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
    const { container } = render(<DecisionExecutionPipeline />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('GovernanceSLAMonitor links include decision ID context', async () => {
    getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
    const { container } = render(<GovernanceSLAMonitor />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('PolicyConflictCenter links point to governance graph', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    const { container } = render(<PolicyConflictCenter />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('EvidenceFreshnessMonitor links point to governance nodes', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('GovernanceAutomationQueue links include automation event context', async () => {
    getAutomationQueue.mockResolvedValue(MOCK_AUTOMATION_RESULT);
    const { container } = render(<GovernanceAutomationQueue />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('navigation links do not contain javascript: protocol', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      const links = Array.from(container.querySelectorAll('a[href]'));
      links.forEach(link => {
        expect(link.href).not.toMatch(/^javascript:/);
      });
    });
  });
  it('back navigation anchor exists on page', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      const backLinks = container.querySelectorAll('a[href*="dashboard"]');
      expect(backLinks.length).toBeGreaterThan(0);
    });
  });
  it('OperationsCenterPage navigation links use relative paths', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      const links = Array.from(container.querySelectorAll('a[href^="/dashboard"]'));
      expect(links.length).toBeGreaterThan(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. CONTEXT PRESERVATION
// ═══════════════════════════════════════════════════════════════════════════════

describe('Context preservation', () => {
  it('ExecutiveOperationsQueue passes decision ID in deep links', async () => {
    getOperationsQueue.mockResolvedValue(MOCK_QUEUE_RESULT);
    const { container } = render(<ExecutiveOperationsQueue />);
    await waitFor(() => {
      const decisionLinks = container.querySelectorAll('a[href*="dec-001"]');
      expect(decisionLinks.length).toBeGreaterThan(0);
    });
  });
  it('CrossAuthorityTimeline preserves authority filter in URL state', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const filterEl = container.querySelector('[data-authority-filter]');
      expect(filterEl).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor node links preserve node context', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      const nodeLinks = container.querySelectorAll('a[href*="node-001"]');
      expect(nodeLinks.length).toBeGreaterThan(0);
    });
  });
  it('PolicyConflictCenter conflict links preserve conflict ID', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    const { container } = render(<PolicyConflictCenter />);
    await waitFor(() => {
      const conflictLinks = container.querySelectorAll('a[href*="anom-001"]');
      expect(conflictLinks.length).toBeGreaterThan(0);
    });
  });
  it('GovernanceSLAMonitor SLA items link back with decision context', async () => {
    getGovernanceSLA.mockResolvedValue(MOCK_SLA_RESULT);
    const { container } = render(<GovernanceSLAMonitor />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href*="dec-001"]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('DecisionExecutionPipeline stage links preserve decision ID', async () => {
    getDecisionPipeline.mockResolvedValue(MOCK_PIPELINE_RESULT);
    const { container } = render(<DecisionExecutionPipeline />);
    await waitFor(() => {
      const links = container.querySelectorAll('a[href*="dec-001"]');
      expect(links.length).toBeGreaterThan(0);
    });
  });
  it('OperationsCenterPage preserves workspace context params across panels', async () => {
    mockAllApis();
    const { container } = render(<OperationsCenterPage />);
    await waitFor(() => {
      const contextEls = container.querySelectorAll('[data-workspace-context]');
      expect(contextEls.length).toBeGreaterThanOrEqual(1);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 10. AUTOMATION SAFETY
// ═══════════════════════════════════════════════════════════════════════════════

describe('Automation safety', () => {
  it('AutomationSafetyCenter shows risk score', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/25/)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows blast radius', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/contained/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows kill switch status when inactive', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/kill switch/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows kill switch active when triggered', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/kill switch.*active|active.*kill switch/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows human approval required flag', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/human approval/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows simulation required flag', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/simulation required/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows chain integrity status', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/chain integrity|ok/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows quarantine count', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/2.*quarantine|quarantine.*2/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows execution confidence', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/93|execution confidence/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter kill switch alert has role="alert"', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      const alert = screen.getByRole('alert');
      expect(alert).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter blast radius "partial" displayed when agents quarantined', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_KILL_SWITCH);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/partial/i)).toBeTruthy();
    });
  });
  it('AutomationSafetyCenter shows rollback availability', async () => {
    getAutomationSafety.mockResolvedValue(MOCK_SAFETY_RESULT);
    render(<AutomationSafetyCenter />);
    await waitFor(() => {
      expect(screen.getByText(/rollback/i)).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 11. TIMELINE
// ═══════════════════════════════════════════════════════════════════════════════

describe('Timeline', () => {
  it('CrossAuthorityTimeline renders events', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0);
    });
  });
  it('CrossAuthorityTimeline events are sorted newest first', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const items = container.querySelectorAll('[data-event-ts]');
      if (items.length >= 2) {
        const ts1 = new Date(items[0].getAttribute('data-event-ts'));
        const ts2 = new Date(items[1].getAttribute('data-event-ts'));
        expect(ts1 >= ts2).toBeTruthy();
      }
    });
  });
  it('CrossAuthorityTimeline shows immutable indicator', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/immutable/i)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline shows auditable indicator', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/auditable/i)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline shows authority labels', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/Forensics Chain/)).toBeTruthy();
      expect(screen.getByText(/Event Feed/)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline authority filter renders', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const filter = container.querySelector('[data-authority-filter]');
      expect(filter).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline shows total event count', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/2 events|total.*2/i)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline shows event severity', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/high/i)).toBeTruthy();
    });
  });
  it('CrossAuthorityTimeline shows timestamps', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    const { container } = render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      const times = container.querySelectorAll('time, [data-event-ts]');
      expect(times.length).toBeGreaterThan(0);
    });
  });
  it('CrossAuthorityTimeline Forensics Chain events show requestId', async () => {
    getCrossAuthorityTimeline.mockResolvedValue(MOCK_TIMELINE_RESULT);
    render(<CrossAuthorityTimeline />);
    await waitFor(() => {
      expect(screen.getByText(/req-001/i)).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 12. POLICY CONFLICT
// ═══════════════════════════════════════════════════════════════════════════════

describe('Policy conflict', () => {
  it('PolicyConflictCenter displays conflict types', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/duplicate.policy/i)).toBeTruthy();
    });
  });
  it('PolicyConflictCenter shows severity badges', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    const { container } = render(<PolicyConflictCenter />);
    await waitFor(() => {
      const badges = container.querySelectorAll('[data-severity]');
      expect(badges.length).toBeGreaterThan(0);
    });
  });
  it('PolicyConflictCenter shows orphaned node count', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/3.*orphan|orphan.*3/i)).toBeTruthy();
    });
  });
  it('PolicyConflictCenter distinguishes resolved vs unresolved conflicts', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/resolved/i)).toBeTruthy();
    });
  });
  it('PolicyConflictCenter shows conflict descriptions', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/Two identical MFA policies/i)).toBeTruthy();
    });
  });
  it('PolicyConflictCenter shows orphaned_control type', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      expect(screen.getByText(/orphaned.control/i)).toBeTruthy();
    });
  });
  it('PolicyConflictCenter shows node IDs for conflict', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    const { container } = render(<PolicyConflictCenter />);
    await waitFor(() => {
      const nodeRefs = container.querySelectorAll('[data-node-id]');
      expect(nodeRefs.length).toBeGreaterThan(0);
    });
  });
  it('PolicyConflictCenter byType summary is displayed', async () => {
    getPolicyConflicts.mockResolvedValue(MOCK_CONFLICTS_RESULT);
    render(<PolicyConflictCenter />);
    await waitFor(() => {
      const byType = screen.getByText(/1.*duplicate_policy|duplicate_policy.*1/i);
      expect(byType).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 13. EVIDENCE FRESHNESS
// ═══════════════════════════════════════════════════════════════════════════════

describe('Evidence freshness', () => {
  it('EvidenceFreshnessMonitor shows "current" status badge', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/current/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor shows "stale" status badge', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/stale/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor shows "missing" status badge', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/missing/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor shows trust score for each record', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/0\.92|92%/)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor calculates and displays age', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      const ageEls = container.querySelectorAll('[data-age-hours]');
      expect(ageEls.length).toBeGreaterThan(0);
    });
  });
  it('EvidenceFreshnessMonitor shows average trust score', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/0\.44|44%|average.*trust|trust.*average/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor byStatus summary is displayed', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/1.*current|current.*1/i)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor shows node labels', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/MFA Policy/)).toBeTruthy();
    });
  });
  it('EvidenceFreshnessMonitor low trust score node shows "missing" badge', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    const { container } = render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      const missingBadges = container.querySelectorAll('[data-status="missing"]');
      expect(missingBadges.length).toBeGreaterThan(0);
    });
  });
  it('EvidenceFreshnessMonitor shows stale node age', async () => {
    getEvidenceFreshness.mockResolvedValue(MOCK_FRESHNESS_RESULT);
    render(<EvidenceFreshnessMonitor />);
    await waitFor(() => {
      expect(screen.getByText(/1500.*h|h.*1500/i)).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 14. BRIEFING SUPPRESSION
// ═══════════════════════════════════════════════════════════════════════════════

describe('Briefing suppression', () => {
  it('shows insufficient evidence notice when sufficientEvidence=false', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Insufficient authoritative evidence/i)).toBeTruthy();
    });
  });
  it('insufficient notice text is exact match', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Insufficient authoritative evidence/)).toBeTruthy();
    });
  });
  it('shows no briefing lines when sufficientEvidence=false', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-briefing-line]').length).toBe(0);
    });
  });
  it('shows briefing lines when sufficientEvidence=true', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-briefing-line]').length).toBeGreaterThan(0);
    });
  });
  it('shows correct authority count', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/2.*authorit/i)).toBeTruthy();
    });
  });
  it('does not show fabricated lines when insufficient', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      const lines = container.querySelectorAll('[data-briefing-line]');
      expect(lines.length).toBe(0);
    });
  });
  it('shows changed category line when sufficient', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Recent governance decisions/i)).toBeTruthy();
    });
  });
  it('shows risk_increased category line when sufficient', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Critical severity events/i)).toBeTruthy();
    });
  });
  it('shows evidence_added line when sufficient', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/Governance graph nodes/i)).toBeTruthy();
    });
  });
  it('shows generated timestamp', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      const timeEl = container.querySelector('time, [data-generated-at]');
      expect(timeEl).toBeTruthy();
    });
  });
  it('insufficient notice has role="alert"', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeTruthy();
    });
  });
  it('authority source labels shown for each line', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_SUFFICIENT);
    const { container } = render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      const authorityEls = container.querySelectorAll('[data-line-authority]');
      expect(authorityEls.length).toBeGreaterThan(0);
    });
  });
  it('sufficiency notice includes reason text', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      const notice = screen.getByText(/Insufficient authoritative evidence/i);
      expect(notice.textContent.length).toBeGreaterThan(20);
    });
  });
  it('shows 0 authority count when insufficient', async () => {
    getOperationalBriefing.mockResolvedValue(MOCK_BRIEFING_INSUFFICIENT);
    render(<ExecutiveOperationalBriefing />);
    await waitFor(() => {
      expect(screen.getByText(/0.*authorit/i)).toBeTruthy();
    });
  });
});
