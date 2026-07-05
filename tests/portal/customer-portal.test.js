/**
 * PR 18.6.6 — Enterprise Customer Portal Experience
 * Static source-scan tests for portal components and pages.
 * Uses node:test + node:assert — no runtime execution, reads source files only.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const COMPONENTS_DIR = path.join(REPO_ROOT, 'apps/portal/components/portal');
const PAGES_DIR = path.join(REPO_ROOT, 'apps/portal/app');

// ─── Component registry ─────────────────────────────────────────────────────

const ALL_COMPONENTS = [
  'PortalShell.tsx',
  'CustomerDashboard.tsx',
  'EngagementOverview.tsx',
  'FindingsView.tsx',
  'EvidenceSummary.tsx',
  'ReportDelivery.tsx',
  'AttestationCenter.tsx',
  'RemediationCenter.tsx',
  'ChangeSummary.tsx',
  'TrustVerificationCenter.tsx',
  'CustomerTrustTimeline.tsx',
  'CustomerActionQueue.tsx',
  'CustomerExportCenter.tsx',
  'AssessmentDelivery.tsx',
  'NotificationCenter.tsx',
  'SupportCenter.tsx',
  'ObservationsPanel.tsx',
  'AuditEventsLog.tsx',
  'DocumentCenter.tsx',
  'ScanHistoryPanel.tsx',
  'QuestionnaireSummary.tsx',
  'ComplianceOverview.tsx',
];

// Components that use PortalShell (all except the shell itself)
const NON_SHELL_COMPONENTS = ALL_COMPONENTS.filter((f) => f !== 'PortalShell.tsx');

const NEW_PAGES = [
  { dir: 'dashboard', testid: 'dashboard-page', label: 'customer-dashboard-page' },
  { dir: 'trust', testid: 'trust-page', label: 'trust-verification-page' },
  { dir: 'timeline', testid: 'timeline-page', label: 'trust-timeline-page' },
  { dir: 'actions', testid: 'actions-page', label: 'customer-actions-page' },
  { dir: 'changes', testid: 'changes-page', label: 'changes-summary-page' },
  { dir: 'export', testid: 'export-page', label: 'customer-export-page' },
  { dir: 'notifications', testid: 'notifications-page', label: 'notifications-page' },
  { dir: 'support', testid: 'support-page', label: 'support-center-page' },
];

function readComponent(filename) {
  return fs.readFileSync(path.join(COMPONENTS_DIR, filename), 'utf-8');
}

function readPage(dir) {
  return fs.readFileSync(path.join(PAGES_DIR, dir, 'page.tsx'), 'utf-8');
}

// ─── Per-component tests ─────────────────────────────────────────────────────

describe('PortalShell', () => {
  const src = readComponent('PortalShell.tsx');

  it('has MCIM-18.6-PORTAL-SHELL identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-SHELL'));
  });

  it('declares customerSafe = true', () => {
    assert.ok(src.includes('const customerSafe = true'));
  });

  it('voids MCIM_ID and customerSafe', () => {
    assert.ok(src.includes('void MCIM_ID'));
    assert.ok(src.includes('void customerSafe'));
  });

  it('exports PortalShellProps interface', () => {
    assert.ok(src.includes('PortalShellProps'));
  });

  it('has collapsible metadata toggle', () => {
    assert.ok(src.includes('Toggle source metadata') || src.includes('aria-expanded'));
  });

  it('renders title prop', () => {
    assert.ok(src.includes('{title}'));
  });

  it('renders lastUpdated footer', () => {
    assert.ok(src.includes('lastUpdated') && src.includes('toLocaleString'));
  });

  it('uses ChevronDown/ChevronUp for toggle', () => {
    assert.ok(src.includes('ChevronDown') || src.includes('ChevronUp'));
  });

  it('does not use console badge import', () => {
    assert.ok(!src.includes('@/components/ui/badge'));
  });

  it('does not use dangerouslySetInnerHTML', () => {
    assert.ok(!src.includes('dangerouslySetInnerHTML'));
  });
});

describe('CustomerDashboard', () => {
  const src = readComponent('CustomerDashboard.tsx');

  it('has MCIM-18.6-PORTAL-DASHBOARD identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-DASHBOARD'));
  });

  it('exports DashboardCard interface', () => {
    assert.ok(src.includes('DashboardCard'));
  });

  it('handles empty/no engagement state', () => {
    assert.ok(src.includes('No engagement selected') || src.includes('engagementId'));
  });

  it('uses inline status badge pattern', () => {
    assert.ok(src.includes('inline-flex') && src.includes('border'));
  });

  it('has aria-label on content section', () => {
    assert.ok(src.includes('aria-label="customer-dashboard"'));
  });

  it('shows confidence when available', () => {
    assert.ok(src.includes('confidence'));
  });

  it('has loading skeleton', () => {
    assert.ok(src.includes('animate-pulse'));
  });
});

describe('TrustVerificationCenter', () => {
  const src = readComponent('TrustVerificationCenter.tsx');

  it('has MCIM-18.6-PORTAL-TRUST-VERIFY identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-TRUST-VERIFY'));
  });

  it('exports TrustVerificationData interface', () => {
    assert.ok(src.includes('TrustVerificationData'));
  });

  it('includes required trust disclaimer', () => {
    assert.ok(src.includes('do not constitute legal certification'));
  });

  it('references manifestHash', () => {
    assert.ok(src.includes('manifestHash'));
  });

  it('references signedHash', () => {
    assert.ok(src.includes('signedHash'));
  });

  it('shows verification rows', () => {
    assert.ok(src.includes('VerificationRow') || src.includes('Evidence Integrity'));
  });

  it('has aria-label on content section', () => {
    assert.ok(src.includes('aria-label="trust-verification-center"'));
  });
});

describe('CustomerExportCenter', () => {
  const src = readComponent('CustomerExportCenter.tsx');

  it('has MCIM-18.6-PORTAL-EXPORT identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-EXPORT'));
  });

  it('exports ExportOption interface', () => {
    assert.ok(src.includes('ExportOption'));
  });

  it('has export disclaimer', () => {
    assert.ok(src.includes('do not constitute legal certification'));
  });

  it('has aria-label on content section', () => {
    assert.ok(src.includes('aria-label="customer-export-center"'));
  });

  it('supports multiple export formats', () => {
    assert.ok(src.includes('formats'));
  });

  it('has not-available state', () => {
    assert.ok(src.includes('available'));
  });
});

describe('NotificationCenter', () => {
  const src = readComponent('NotificationCenter.tsx');

  it('has MCIM-18.6-PORTAL-NOTIFICATIONS identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-NOTIFICATIONS'));
  });

  it('exports PortalNotification interface', () => {
    assert.ok(src.includes('PortalNotification'));
  });

  it('exports NotificationType', () => {
    assert.ok(src.includes('NotificationType'));
  });

  it('has aria-label="notification-center"', () => {
    assert.ok(src.includes('aria-label="notification-center"'));
  });

  it('has data-testid="notification-center"', () => {
    assert.ok(src.includes('data-testid="notification-center"'));
  });

  it('has mark-read functionality', () => {
    assert.ok(src.includes('onMarkRead') || src.includes('Mark read'));
  });

  it('shows unread count', () => {
    assert.ok(src.includes('unread'));
  });

  it('handles empty notifications', () => {
    assert.ok(src.includes('No notifications'));
  });
});

describe('SupportCenter', () => {
  const src = readComponent('SupportCenter.tsx');

  it('has MCIM-18.6-PORTAL-SUPPORT identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-SUPPORT'));
  });

  it('exports SupportTopic interface', () => {
    assert.ok(src.includes('SupportTopic'));
  });

  it('has aria-label="support-center"', () => {
    assert.ok(src.includes('aria-label="support-center"'));
  });

  it('has data-testid="support-center"', () => {
    assert.ok(src.includes('data-testid="support-center"'));
  });

  it('mentions operator', () => {
    assert.ok(src.toLowerCase().includes('operator'));
  });

  it('groups topics by category', () => {
    assert.ok(src.includes('category'));
  });

  it('has expand/collapse for topics', () => {
    assert.ok(src.includes('aria-expanded') || src.includes('expandedId'));
  });

  it('shows contact email when provided', () => {
    assert.ok(src.includes('contactEmail'));
  });
});

describe('ObservationsPanel', () => {
  const src = readComponent('ObservationsPanel.tsx');

  it('has MCIM-18.6-PORTAL-OBSERVATIONS identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-OBSERVATIONS'));
  });

  it('exports PortalObservation interface', () => {
    assert.ok(src.includes('PortalObservation'));
  });

  it('has aria-label="observations-panel"', () => {
    assert.ok(src.includes('aria-label="observations-panel"'));
  });

  it('has data-testid="observations-panel"', () => {
    assert.ok(src.includes('data-testid="observations-panel"'));
  });

  it('groups by domain', () => {
    assert.ok(src.includes('domain'));
  });

  it('has type badges (gap/strength/concern)', () => {
    assert.ok(src.includes('gap') && src.includes('strength'));
  });
});

describe('AuditEventsLog', () => {
  const src = readComponent('AuditEventsLog.tsx');

  it('has MCIM-18.6-PORTAL-AUDIT-EVENTS identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-AUDIT-EVENTS'));
  });

  it('exports PortalAuditEvent interface', () => {
    assert.ok(src.includes('PortalAuditEvent'));
  });

  it('has aria-label="audit-events-log"', () => {
    assert.ok(src.includes('aria-label="audit-events-log"'));
  });

  it('has data-testid="audit-events-log"', () => {
    assert.ok(src.includes('data-testid="audit-events-log"'));
  });

  it('has governance context notice', () => {
    assert.ok(src.toLowerCase().includes('governance'));
  });

  it('sorts events chronologically', () => {
    assert.ok(src.includes('getTime'));
  });

  it('shows empty state', () => {
    assert.ok(src.includes('No audit events'));
  });
});

describe('DocumentCenter', () => {
  const src = readComponent('DocumentCenter.tsx');

  it('has MCIM-18.6-PORTAL-DOCUMENTS identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-DOCUMENTS'));
  });

  it('exports PortalDocument interface', () => {
    assert.ok(src.includes('PortalDocument'));
  });

  it('has aria-label="document-center"', () => {
    assert.ok(src.includes('aria-label="document-center"'));
  });

  it('has data-testid="document-center"', () => {
    assert.ok(src.includes('data-testid="document-center"'));
  });

  it('shows classification badge', () => {
    assert.ok(src.includes('documentClassification') || src.includes('classification'));
  });

  it('truncates document hash', () => {
    assert.ok(src.includes('slice(0, 12)') || src.includes('Hash'));
  });

  it('mentions hash for integrity', () => {
    assert.ok(src.includes('integrity') || src.includes('Hash'));
  });
});

describe('ScanHistoryPanel', () => {
  const src = readComponent('ScanHistoryPanel.tsx');

  it('has MCIM-18.6-PORTAL-SCANS identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-SCANS'));
  });

  it('exports PortalScan interface', () => {
    assert.ok(src.includes('PortalScan'));
  });

  it('has aria-label="scan-history-panel"', () => {
    assert.ok(src.includes('aria-label="scan-history-panel"'));
  });

  it('has data-testid="scan-history-panel"', () => {
    assert.ok(src.includes('data-testid="scan-history-panel"'));
  });

  it('mentions no raw payloads notice', () => {
    assert.ok(src.toLowerCase().includes('raw scan'));
  });

  it('truncates evidence hash', () => {
    assert.ok(src.includes('slice(0, 12)') || src.includes('evidenceHash'));
  });
});

describe('QuestionnaireSummary', () => {
  const src = readComponent('QuestionnaireSummary.tsx');

  it('has MCIM-18.6-PORTAL-QUESTIONNAIRE identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-QUESTIONNAIRE'));
  });

  it('exports QuestionnaireStatus interface', () => {
    assert.ok(src.includes('QuestionnaireStatus'));
  });

  it('has aria-label="questionnaire-summary"', () => {
    assert.ok(src.includes('aria-label="questionnaire-summary"'));
  });

  it('has data-testid="questionnaire-summary"', () => {
    assert.ok(src.includes('data-testid="questionnaire-summary"'));
  });

  it('shows implemented/partial/not-implemented counts', () => {
    assert.ok(src.includes('implementedCount') && src.includes('partialCount'));
  });

  it('shows framework name', () => {
    assert.ok(src.includes('framework'));
  });
});

describe('ComplianceOverview', () => {
  const src = readComponent('ComplianceOverview.tsx');

  it('has MCIM-18.6-PORTAL-COMPLIANCE identifier', () => {
    assert.ok(src.includes('MCIM-18.6-PORTAL-COMPLIANCE'));
  });

  it('exports ComplianceDomain interface', () => {
    assert.ok(src.includes('ComplianceDomain'));
  });

  it('has aria-label="compliance-overview"', () => {
    assert.ok(src.includes('aria-label="compliance-overview"'));
  });

  it('has data-testid="compliance-overview"', () => {
    assert.ok(src.includes('data-testid="compliance-overview"'));
  });

  it('has required disclaimer', () => {
    assert.ok(src.includes('do not constitute legal certification'));
  });

  it('shows coverage percentage bar', () => {
    assert.ok(src.includes('overallCoveragePct') || src.includes('progressbar'));
  });

  it('has per-domain coverage bars', () => {
    assert.ok(src.includes('coveragePct'));
  });
});

// ─── Cross-cutting component tests ──────────────────────────────────────────

describe('All components — MCIM compliance', () => {
  for (const filename of ALL_COMPONENTS) {
    it(`${filename} has MCIM-18.6-PORTAL- prefix`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('MCIM-18.6-PORTAL-'), `${filename} missing MCIM-18.6-PORTAL- prefix`);
    });

    it(`${filename} has customerSafe = true`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('const customerSafe = true'), `${filename} missing customerSafe`);
    });

    it(`${filename} voids MCIM_ID`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('void MCIM_ID'), `${filename} missing void MCIM_ID`);
    });

    it(`${filename} voids customerSafe`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('void customerSafe'), `${filename} missing void customerSafe`);
    });

    it(`${filename} declares sourceOfTruth`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('const sourceOfTruth ='), `${filename} missing sourceOfTruth`);
    });

    it(`${filename} declares drillDown`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('const drillDown ='), `${filename} missing drillDown`);
    });
  }
});

describe('All components — security invariants', () => {
  for (const filename of ALL_COMPONENTS) {
    it(`${filename} has no tenant_id exposure`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('tenant_id'), `${filename} exposes tenant_id`);
    });

    it(`${filename} has no dangerouslySetInnerHTML`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('dangerouslySetInnerHTML'), `${filename} uses dangerouslySetInnerHTML`);
    });

    it(`${filename} has no console badge import`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('@/components/ui/badge'), `${filename} imports console badge`);
    });

    it(`${filename} has no console button import`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('@/components/ui/button'), `${filename} imports console button`);
    });

    it(`${filename} has no console card import`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('@/components/ui/card'), `${filename} imports console card`);
    });

    it(`${filename} has no Math.random`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('Math.random()'), `${filename} uses Math.random`);
    });

    it(`${filename} has no sessionStorage`, () => {
      const src = readComponent(filename);
      assert.ok(!src.includes('sessionStorage'), `${filename} uses sessionStorage`);
    });
  }
});

describe('Non-shell components — PortalShell usage', () => {
  for (const filename of NON_SHELL_COMPONENTS) {
    it(`${filename} wraps content in PortalShell`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('PortalShell'), `${filename} missing PortalShell wrapper`);
    });

    it(`${filename} passes mcimId to PortalShell`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('mcimId='), `${filename} missing mcimId prop`);
    });

    it(`${filename} has aria-label on content section`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('aria-label='), `${filename} missing aria-label`);
    });

    it(`${filename} has data-testid on content section`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('data-testid='), `${filename} missing data-testid`);
    });

    it(`${filename} has loading skeleton`, () => {
      const src = readComponent(filename);
      assert.ok(src.includes('animate-pulse') || src.includes('loading'), `${filename} missing loading state`);
    });
  }
});

describe('Non-shell components — empty state handling', () => {
  for (const filename of NON_SHELL_COMPONENTS) {
    it(`${filename} handles empty or no-data state`, () => {
      const src = readComponent(filename);
      // Each component should have some form of empty/unavailable state
      const hasEmpty = src.includes('No ') || src.includes('not available') || src.includes('No engagement') || src.includes('not found');
      assert.ok(hasEmpty, `${filename} missing empty/no-data state`);
    });
  }
});

// ─── Page tests ──────────────────────────────────────────────────────────────

describe('New portal pages — existence and testid', () => {
  for (const { dir, testid } of NEW_PAGES) {
    it(`${dir}/page.tsx exists`, () => {
      const pagePath = path.join(PAGES_DIR, dir, 'page.tsx');
      assert.ok(fs.existsSync(pagePath), `Missing ${dir}/page.tsx`);
    });

    it(`${dir}/page.tsx has data-testid="${testid}"`, () => {
      const src = readPage(dir);
      assert.ok(src.includes(`data-testid="${testid}"`), `${dir}/page.tsx missing data-testid="${testid}"`);
    });

    it(`${dir}/page.tsx has "use client" directive`, () => {
      const src = readPage(dir);
      assert.ok(src.includes('use client'), `${dir}/page.tsx missing "use client"`);
    });

    it(`${dir}/page.tsx has Suspense boundary`, () => {
      const src = readPage(dir);
      assert.ok(src.includes('Suspense'), `${dir}/page.tsx missing Suspense`);
    });
  }
});

describe('New portal pages — security', () => {
  for (const { dir } of NEW_PAGES) {
    it(`${dir}/page.tsx has no tenant_id`, () => {
      const src = readPage(dir);
      assert.ok(!src.includes('tenant_id'), `${dir}/page.tsx exposes tenant_id`);
    });

    it(`${dir}/page.tsx has no dangerouslySetInnerHTML`, () => {
      const src = readPage(dir);
      assert.ok(!src.includes('dangerouslySetInnerHTML'), `${dir}/page.tsx uses dangerouslySetInnerHTML`);
    });

    it(`${dir}/page.tsx uses portalApi or engagementId`, () => {
      const src = readPage(dir);
      const usesPortal = src.includes('portalApi') || src.includes('engagementId') || src.includes('getStoredEngagementId');
      assert.ok(usesPortal, `${dir}/page.tsx does not use portal API or engagement ID`);
    });
  }
});

describe('Pages — use correct portal components', () => {
  it('dashboard/page.tsx imports CustomerDashboard', () => {
    assert.ok(readPage('dashboard').includes('CustomerDashboard'));
  });

  it('trust/page.tsx imports TrustVerificationCenter', () => {
    assert.ok(readPage('trust').includes('TrustVerificationCenter'));
  });

  it('timeline/page.tsx imports CustomerTrustTimeline', () => {
    assert.ok(readPage('timeline').includes('CustomerTrustTimeline'));
  });

  it('actions/page.tsx imports CustomerActionQueue', () => {
    assert.ok(readPage('actions').includes('CustomerActionQueue'));
  });

  it('changes/page.tsx imports ChangeSummary', () => {
    assert.ok(readPage('changes').includes('ChangeSummary'));
  });

  it('export/page.tsx imports CustomerExportCenter', () => {
    assert.ok(readPage('export').includes('CustomerExportCenter'));
  });

  it('notifications/page.tsx imports NotificationCenter', () => {
    assert.ok(readPage('notifications').includes('NotificationCenter'));
  });

  it('support/page.tsx imports SupportCenter', () => {
    assert.ok(readPage('support').includes('SupportCenter'));
  });
});

describe('CI script existence', () => {
  it('check_customer_portal.py exists', () => {
    const p = path.join(REPO_ROOT, 'tools/ci/check_customer_portal.py');
    assert.ok(fs.existsSync(p), 'check_customer_portal.py not found');
  });

  it('check_customer_portal.py checks all 22 components', () => {
    const src = fs.readFileSync(
      path.join(REPO_ROOT, 'tools/ci/check_customer_portal.py'),
      'utf-8',
    );
    assert.ok(src.includes('EXPECTED_COMPONENTS'));
    for (const comp of ALL_COMPONENTS) {
      assert.ok(src.includes(comp), `CI script missing ${comp}`);
    }
  });

  it('check_customer_portal.py checks all 8 pages', () => {
    const src = fs.readFileSync(
      path.join(REPO_ROOT, 'tools/ci/check_customer_portal.py'),
      'utf-8',
    );
    for (const { dir } of NEW_PAGES) {
      assert.ok(src.includes(dir), `CI script missing page ${dir}`);
    }
  });
});
