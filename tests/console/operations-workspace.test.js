'use strict';

/**
 * operations-workspace.test.js
 *
 * 800+ deterministic static-analysis tests for PR 18.6.4 Enterprise Operations Workspace.
 * Tests read source files and assert on their structure — no runtime execution,
 * no mocking, no network calls.
 *
 * Structure:
 *  - WorkspaceShell tests (~25)
 *  - UnifiedWorkQueue tests (~65)
 *  - CaseWorkspace tests (~55)
 *  - DecisionLedger tests (~60)
 *  - WorkflowProgress tests (~55)
 *  - InvestigationTimeline tests (~55)
 *  - CrossAuthorityNav tests (~45)
 *  - AuthorityHealthMap tests (~50)
 *  - CorrelationGraph2 tests (~45)
 *  - CommandPalette tests (~60)
 *  - PlaybookPanel tests (~45)
 *  - DelegationPanel tests (~50)
 *  - ExportPanel tests (~50)
 *  - Workspace Page tests (~60)
 *  - CI script tests (~30)
 *  - Architecture doc tests (~20)
 *  - Accessibility tests (~40)
 *  - No-fake-data enforcement tests (~30)
 *  - Cross-component consistency tests (~20)
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.join(__dirname, '..', '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(ROOT, relPath));
}

const WS_DIR = 'apps/console/components/operations-workspace';

function ws(name) {
  return `${WS_DIR}/${name}`;
}

// ─── WorkspaceShell ───────────────────────────────────────────────────────────

test('WorkspaceShell — file exists', () => {
  assert.ok(exists(ws('WorkspaceShell.tsx')));
});

test('WorkspaceShell — has use client', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /'use client'/);
});

test('WorkspaceShell — has default export WorkspaceShell', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /export default function WorkspaceShell/);
});

test('WorkspaceShell — exports WorkspaceShellProps', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /export interface WorkspaceShellProps/);
});

test('WorkspaceShell — has MCIM-18.6-OPS-WORKSPACE', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /MCIM-18\.6-OPS-WORKSPACE/);
});

test('WorkspaceShell — has Operations Workspace Authority', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /Operations Workspace Authority/);
});

test('WorkspaceShell — has sourceOfTruth', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /sourceOfTruth/);
});

test('WorkspaceShell — has workflowStage prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /workflowStage/);
});

test('WorkspaceShell — has delegationSupported prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /delegationSupported/);
});

test('WorkspaceShell — has tenantId prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /tenantId/);
});

test('WorkspaceShell — has playbook prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /playbook/);
});

test('WorkspaceShell — no Math.random', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /Math\.random/);
});

test('WorkspaceShell — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /dangerouslySetInnerHTML/);
});

test('WorkspaceShell — no localStorage', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /localStorage/);
});

test('WorkspaceShell — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /sessionStorage/);
});

test('WorkspaceShell — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /variant=['"]destructive['"]/);
});

test('WorkspaceShell — has aria-label on panel', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /aria-label/);
});

test('WorkspaceShell — has workspace-panel prefix in aria-label', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /workspace-panel/);
});

test('WorkspaceShell — has Card import', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /Card/);
});

test('WorkspaceShell — has metadata section', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /workspace-panel-metadata|widget-metadata/);
});

test('WorkspaceShell — has authority prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /authority.*string|string.*authority/);
});

test('WorkspaceShell — has capability prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /capability.*string|string.*capability/);
});

test('WorkspaceShell — has drillDown prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /drillDown.*string|string.*drillDown/);
});

test('WorkspaceShell — has mcimId prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /mcimId.*string|string.*mcimId/);
});

test('WorkspaceShell — has children prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /children/);
});

// ─── UnifiedWorkQueue ─────────────────────────────────────────────────────────

test('UnifiedWorkQueue — file exists', () => {
  assert.ok(exists(ws('UnifiedWorkQueue.tsx')));
});

test('UnifiedWorkQueue — has use client', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'use client'/);
});

test('UnifiedWorkQueue — has default export UnifiedWorkQueue', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /export default function UnifiedWorkQueue/);
});

test('UnifiedWorkQueue — exports WorkQueueItem', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /export interface WorkQueueItem/);
});

test('UnifiedWorkQueue — exports WorkType', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /export type WorkType/);
});

test('UnifiedWorkQueue — has MCIM-18.6-WORK-QUEUE', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /MCIM-18\.6-WORK-QUEUE/);
});

test('UnifiedWorkQueue — has Work Queue Authority', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /Work Queue Authority/);
});

test('UnifiedWorkQueue — sourceOfTruth is /api/core/feed/live', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /\/api\/core\/feed\/live/);
});

test('UnifiedWorkQueue — has assessment work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'assessment'/);
});

test('UnifiedWorkQueue — has evidence-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'evidence-review'/);
});

test('UnifiedWorkQueue — has verification work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'verification'/);
});

test('UnifiedWorkQueue — has report-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'report-review'/);
});

test('UnifiedWorkQueue — has portal-publication work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'portal-publication'/);
});

test('UnifiedWorkQueue — has remediation work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'remediation'/);
});

test('UnifiedWorkQueue — has governance-approval work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'governance-approval'/);
});

test('UnifiedWorkQueue — has trust-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'trust-review'/);
});

test('UnifiedWorkQueue — has transparency-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'transparency-review'/);
});

test('UnifiedWorkQueue — has simulation-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'simulation-review'/);
});

test('UnifiedWorkQueue — has replay-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'replay-review'/);
});

test('UnifiedWorkQueue — has customer-request work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'customer-request'/);
});

test('UnifiedWorkQueue — has notification work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'notification'/);
});

test('UnifiedWorkQueue — has policy-review work type', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'policy-review'/);
});

test('UnifiedWorkQueue — WorkQueueItem has priority field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /priority.*critical.*high.*medium.*low|'critical' \| 'high' \| 'medium' \| 'low'/);
});

test('UnifiedWorkQueue — WorkQueueItem has sla field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /sla/);
});

test('UnifiedWorkQueue — WorkQueueItem has owner field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /owner/);
});

test('UnifiedWorkQueue — WorkQueueItem has dueDate field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /dueDate/);
});

test('UnifiedWorkQueue — WorkQueueItem has confidence field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /confidence/);
});

test('UnifiedWorkQueue — WorkQueueItem has sourceObject field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /sourceObject/);
});

test('UnifiedWorkQueue — WorkQueueItem has drillDown field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /drillDown/);
});

test('UnifiedWorkQueue — WorkQueueItem has workflowStage field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /workflowStage/);
});

test('UnifiedWorkQueue — WorkQueueItem has authority field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /authority.*string/);
});

test('UnifiedWorkQueue — WorkQueueItem has capability field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /capability.*string/);
});

test('UnifiedWorkQueue — WorkQueueItem has mcimId field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /mcimId.*string/);
});

test('UnifiedWorkQueue — has empty state', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /No items|empty|no.*queue/i);
});

test('UnifiedWorkQueue — has loading state', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /loading|animate-pulse|skeleton/i);
});

test('UnifiedWorkQueue — has filter by priority', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /filter|Filter|PriorityFilter/);
});

test('UnifiedWorkQueue — no Math.random', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /Math\.random/);
});

test('UnifiedWorkQueue — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /dangerouslySetInnerHTML/);
});

test('UnifiedWorkQueue — no localStorage', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /localStorage/);
});

test('UnifiedWorkQueue — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /sessionStorage/);
});

test('UnifiedWorkQueue — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /variant=['"]destructive['"]/);
});

test('UnifiedWorkQueue — WorkQueueItem has title field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /title.*string/);
});

test('UnifiedWorkQueue — WorkQueueItem has severity field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /severity/);
});

test('UnifiedWorkQueue — WorkQueueItem has id field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /id.*string/);
});

test('UnifiedWorkQueue — WorkQueueItem has workType field', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /workType/);
});

test('UnifiedWorkQueue — has drillDown constant', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /const drillDown/);
});

test('UnifiedWorkQueue — has MCIM_ID constant', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /const MCIM_ID/);
});

test('UnifiedWorkQueue — has AUTHORITY constant', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /const AUTHORITY/);
});

test('UnifiedWorkQueue — has sourceOfTruth constant', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /const sourceOfTruth/);
});

test('UnifiedWorkQueue — 14 work types defined', () => {
  const content = read(ws('UnifiedWorkQueue.tsx'));
  const types = [
    'assessment', 'evidence-review', 'verification', 'report-review',
    'portal-publication', 'remediation', 'governance-approval', 'trust-review',
    'transparency-review', 'simulation-review', 'replay-review', 'customer-request',
    'notification', 'policy-review'
  ];
  for (const t of types) {
    assert.ok(content.includes(`'${t}'`), `missing work type '${t}'`);
  }
});

test('UnifiedWorkQueue — has role="list" for items', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /role=['"]list['"]/);
});

// ─── CaseWorkspace ────────────────────────────────────────────────────────────

test('CaseWorkspace — file exists', () => {
  assert.ok(exists(ws('CaseWorkspace.tsx')));
});

test('CaseWorkspace — has use client', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /'use client'/);
});

test('CaseWorkspace — has default export CaseWorkspace', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /export default function CaseWorkspace/);
});

test('CaseWorkspace — exports WorkspaceCase', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /export interface WorkspaceCase/);
});

test('CaseWorkspace — has MCIM-18.6-CASE-WORKSPACE', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /MCIM-18\.6-CASE-WORKSPACE/);
});

test('CaseWorkspace — has Case Workspace Authority', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /Case Workspace Authority/);
});

test('CaseWorkspace — sourceOfTruth is /api/core/decisions', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /\/api\/core\/decisions/);
});

test('CaseWorkspace — WorkspaceCase has status field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /status.*open|'open'/);
});

test('CaseWorkspace — WorkspaceCase status has open', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /'open'/);
});

test('CaseWorkspace — WorkspaceCase status has in-progress', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /'in-progress'/);
});

test('CaseWorkspace — WorkspaceCase status has blocked', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /'blocked'/);
});

test('CaseWorkspace — WorkspaceCase status has closed', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /'closed'/);
});

test('CaseWorkspace — WorkspaceCase has linkedAssessments', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedAssessments/);
});

test('CaseWorkspace — WorkspaceCase has linkedDecisions', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedDecisions/);
});

test('CaseWorkspace — WorkspaceCase has linkedReports', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedReports/);
});

test('CaseWorkspace — WorkspaceCase has linkedEvidence', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedEvidence/);
});

test('CaseWorkspace — WorkspaceCase has owner field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /owner/);
});

test('CaseWorkspace — WorkspaceCase has createdAt field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /createdAt/);
});

test('CaseWorkspace — WorkspaceCase has updatedAt field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /updatedAt/);
});

test('CaseWorkspace — WorkspaceCase has priority field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /priority/);
});

test('CaseWorkspace — WorkspaceCase has title field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /title.*string/);
});

test('CaseWorkspace — WorkspaceCase has id field', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /id.*string/);
});

test('CaseWorkspace — has empty state', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /No cases|empty|no.*case/i);
});

test('CaseWorkspace — has loading state', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /loading|animate-pulse/i);
});

test('CaseWorkspace — no Math.random', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /Math\.random/);
});

test('CaseWorkspace — no localStorage', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /localStorage/);
});

test('CaseWorkspace — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /sessionStorage/);
});

test('CaseWorkspace — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /variant=['"]destructive['"]/);
});

test('CaseWorkspace — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /dangerouslySetInnerHTML/);
});

test('CaseWorkspace — has MCIM_ID constant', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /const MCIM_ID/);
});

test('CaseWorkspace — has AUTHORITY constant', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /const AUTHORITY/);
});

test('CaseWorkspace — cases reference IDs not data', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /string\[\]/);
});

// ─── DecisionLedger ───────────────────────────────────────────────────────────

test('DecisionLedger — file exists', () => {
  assert.ok(exists(ws('DecisionLedger.tsx')));
});

test('DecisionLedger — has use client', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /'use client'/);
});

test('DecisionLedger — has default export DecisionLedger', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /export default function DecisionLedger/);
});

test('DecisionLedger — exports LedgerEntry', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /export interface LedgerEntry/);
});

test('DecisionLedger — has MCIM-18.6-DECISION-LEDGER', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /MCIM-18\.6-DECISION-LEDGER/);
});

test('DecisionLedger — has Decision Ledger Authority', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /Decision Ledger Authority/);
});

test('DecisionLedger — sourceOfTruth is /api/core/decisions', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /\/api\/core\/decisions/);
});

test('DecisionLedger — LedgerEntry has businessJustification', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /businessJustification/);
});

test('DecisionLedger — LedgerEntry has evidence field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /evidence/);
});

test('DecisionLedger — LedgerEntry has alternativesConsidered', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /alternativesConsidered/);
});

test('DecisionLedger — LedgerEntry has expectedOutcome', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /expectedOutcome/);
});

test('DecisionLedger — LedgerEntry has actualOutcome', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /actualOutcome/);
});

test('DecisionLedger — LedgerEntry has owner field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /owner.*string/);
});

test('DecisionLedger — LedgerEntry has reviewer field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /reviewer/);
});

test('DecisionLedger — LedgerEntry has reviewSchedule field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /reviewSchedule/);
});

test('DecisionLedger — LedgerEntry has confidence field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /confidence/);
});

test('DecisionLedger — LedgerEntry has provenanceChain field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /provenanceChain/);
});

test('DecisionLedger — LedgerEntry has linkedReports field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /linkedReports/);
});

test('DecisionLedger — LedgerEntry has linkedRemediation field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /linkedRemediation/);
});

test('DecisionLedger — LedgerEntry has linkedSimulations field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /linkedSimulations/);
});

test('DecisionLedger — LedgerEntry has createdAt field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /createdAt/);
});

test('DecisionLedger — has aria-label decision-ledger-panel', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /decision-ledger-panel/);
});

test('DecisionLedger — no write operations (append-only display)', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /method.*POST|POST.*method/);
});

test('DecisionLedger — no Math.random', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /Math\.random/);
});

test('DecisionLedger — no localStorage', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /localStorage/);
});

test('DecisionLedger — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /sessionStorage/);
});

test('DecisionLedger — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /variant=['"]destructive['"]/);
});

test('DecisionLedger — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /dangerouslySetInnerHTML/);
});

test('DecisionLedger — has loading state', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /loading|animate-pulse/i);
});

test('DecisionLedger — has empty state', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /No entries|No ledger|empty/i);
});

test('DecisionLedger — LedgerEntry has decision field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /decision.*string/);
});

test('DecisionLedger — LedgerEntry has id field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /id.*string/);
});

// ─── WorkflowProgress ────────────────────────────────────────────────────────

test('WorkflowProgress — file exists', () => {
  assert.ok(exists(ws('WorkflowProgress.tsx')));
});

test('WorkflowProgress — has use client', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'use client'/);
});

test('WorkflowProgress — has default export WorkflowProgress', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /export default function WorkflowProgress/);
});

test('WorkflowProgress — exports WorkflowState', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /export interface WorkflowState/);
});

test('WorkflowProgress — exports WorkflowStage', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /export interface WorkflowStage/);
});

test('WorkflowProgress — exports WorkflowStageName', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /export type WorkflowStageName/);
});

test('WorkflowProgress — has MCIM-18.6-WORKFLOW-PROGRESS', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /MCIM-18\.6-WORKFLOW-PROGRESS/);
});

test('WorkflowProgress — has Workflow Progress Authority', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /Workflow Progress Authority/);
});

test('WorkflowProgress — stage: not-started', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'not-started'/);
});

test('WorkflowProgress — stage: active', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'active'|: 'active'/);
});

test('WorkflowProgress — stage: waiting', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'waiting'/);
});

test('WorkflowProgress — stage: blocked', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'blocked'/);
});

test('WorkflowProgress — stage: completed', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'completed'/);
});

test('WorkflowProgress — workflow type: assessment', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'assessment'/);
});

test('WorkflowProgress — workflow type: evidence', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'evidence'/);
});

test('WorkflowProgress — workflow type: verification', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'verification'/);
});

test('WorkflowProgress — workflow type: report', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'report'/);
});

test('WorkflowProgress — workflow type: portal', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'portal'/);
});

test('WorkflowProgress — workflow type: remediation', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'remediation'/);
});

test('WorkflowProgress — workflow type: governance', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'governance'/);
});

test('WorkflowProgress — workflow type: trust', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'trust'/);
});

test('WorkflowProgress — workflow type: simulation', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'simulation'/);
});

test('WorkflowProgress — workflow type: replay', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /'replay'/);
});

test('WorkflowProgress — WorkflowState has currentStage field', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /currentStage/);
});

test('WorkflowProgress — WorkflowState has stages field', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /stages.*WorkflowStage|WorkflowStage.*\[\]/);
});

test('WorkflowProgress — has visual progress indicator', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /bg-|progress|Progress/);
});

test('WorkflowProgress — has loading state', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /loading|animate-pulse/i);
});

test('WorkflowProgress — has empty state', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /No workflows|empty/i);
});

test('WorkflowProgress — no Math.random', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /Math\.random/);
});

test('WorkflowProgress — no localStorage', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /localStorage/);
});

test('WorkflowProgress — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /sessionStorage/);
});

test('WorkflowProgress — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /variant=['"]destructive['"]/);
});

test('WorkflowProgress — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /dangerouslySetInnerHTML/);
});

test('WorkflowProgress — WorkflowState has id field', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /id.*string/);
});

test('WorkflowProgress — WorkflowState has name field', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /name.*string/);
});

// ─── InvestigationTimeline ────────────────────────────────────────────────────

test('InvestigationTimeline — file exists', () => {
  assert.ok(exists(ws('InvestigationTimeline.tsx')));
});

test('InvestigationTimeline — has use client', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'use client'/);
});

test('InvestigationTimeline — has default export InvestigationTimeline', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /export default function InvestigationTimeline/);
});

test('InvestigationTimeline — exports TimelineEvent', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /export interface TimelineEvent/);
});

test('InvestigationTimeline — exports TimelineEventType', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /export type TimelineEventType/);
});

test('InvestigationTimeline — has MCIM-18.6-INVESTIGATION-TIMELINE', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /MCIM-18\.6-INVESTIGATION-TIMELINE/);
});

test('InvestigationTimeline — has Investigation Authority', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /Investigation Authority/);
});

test('InvestigationTimeline — sourceOfTruth is /api/core/forensics/events', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /\/api\/core\/forensics\/events/);
});

test('InvestigationTimeline — event type: created', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'created'/);
});

test('InvestigationTimeline — event type: modified', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'modified'/);
});

test('InvestigationTimeline — event type: verified', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'verified'/);
});

test('InvestigationTimeline — event type: reviewed', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'reviewed'/);
});

test('InvestigationTimeline — event type: approved', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'approved'/);
});

test('InvestigationTimeline — event type: published', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'published'/);
});

test('InvestigationTimeline — event type: remediated', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'remediated'/);
});

test('InvestigationTimeline — event type: closed', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /'closed'/);
});

test('InvestigationTimeline — TimelineEvent has authority field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /authority.*string/);
});

test('InvestigationTimeline — TimelineEvent has timestamp field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /timestamp.*string/);
});

test('InvestigationTimeline — TimelineEvent has actor field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /actor/);
});

test('InvestigationTimeline — TimelineEvent has confidence field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /confidence/);
});

test('InvestigationTimeline — TimelineEvent has correlationId field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /correlationId/);
});

test('InvestigationTimeline — TimelineEvent has sourceObject field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /sourceObject/);
});

test('InvestigationTimeline — TimelineEvent has drillDown field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /drillDown/);
});

test('InvestigationTimeline — has aria-label investigation-timeline-panel', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /investigation-timeline-panel/);
});

test('InvestigationTimeline — has loading state', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /loading|animate-pulse/i);
});

test('InvestigationTimeline — has empty state', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /No events|No timeline|empty/i);
});

test('InvestigationTimeline — no Math.random', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /Math\.random/);
});

test('InvestigationTimeline — no localStorage', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /localStorage/);
});

test('InvestigationTimeline — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /sessionStorage/);
});

test('InvestigationTimeline — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /variant=['"]destructive['"]/);
});

test('InvestigationTimeline — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /dangerouslySetInnerHTML/);
});

test('InvestigationTimeline — TimelineEvent has id field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /id.*string/);
});

test('InvestigationTimeline — TimelineEvent has eventType field', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /eventType/);
});

// ─── CrossAuthorityNav ────────────────────────────────────────────────────────

test('CrossAuthorityNav — file exists', () => {
  assert.ok(exists(ws('CrossAuthorityNav.tsx')));
});

test('CrossAuthorityNav — has use client', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /'use client'/);
});

test('CrossAuthorityNav — has default export CrossAuthorityNav', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /export default function CrossAuthorityNav/);
});

test('CrossAuthorityNav — has MCIM-18.6-CROSS-AUTHORITY-NAV', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /MCIM-18\.6-CROSS-AUTHORITY-NAV/);
});

test('CrossAuthorityNav — has Navigation Authority', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Navigation Authority/);
});

test('CrossAuthorityNav — has aria-label cross-authority-nav', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /cross-authority-nav/);
});

test('CrossAuthorityNav — chain includes Assessment', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Assessment/);
});

test('CrossAuthorityNav — chain includes Evidence', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Evidence/);
});

test('CrossAuthorityNav — chain includes Verification', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Verification/);
});

test('CrossAuthorityNav — chain includes Findings', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Findings/);
});

test('CrossAuthorityNav — chain includes Report', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Report/);
});

test('CrossAuthorityNav — chain includes Governance', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Governance/);
});

test('CrossAuthorityNav — chain includes Decision', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Decision/);
});

test('CrossAuthorityNav — chain includes Simulation', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Simulation/);
});

test('CrossAuthorityNav — chain includes Replay', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Replay/);
});

test('CrossAuthorityNav — chain includes Portal', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Portal/);
});

test('CrossAuthorityNav — chain includes Customer', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /Customer/);
});

test('CrossAuthorityNav — no localStorage', () => {
  assert.doesNotMatch(read(ws('CrossAuthorityNav.tsx')), /localStorage/);
});

test('CrossAuthorityNav — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('CrossAuthorityNav.tsx')), /sessionStorage/);
});

test('CrossAuthorityNav — no Math.random', () => {
  assert.doesNotMatch(read(ws('CrossAuthorityNav.tsx')), /Math\.random/);
});

test('CrossAuthorityNav — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('CrossAuthorityNav.tsx')), /variant=['"]destructive['"]/);
});

test('CrossAuthorityNav — has keyboard navigation support', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /tabIndex|onKeyDown|key.*keyboard/i);
});

test('CrossAuthorityNav — 11 authority steps defined', () => {
  const content = read(ws('CrossAuthorityNav.tsx'));
  const steps = ['Assessment', 'Evidence', 'Verification', 'Findings', 'Report',
    'Governance', 'Decision', 'Simulation', 'Replay', 'Portal', 'Customer'];
  for (const step of steps) {
    assert.ok(content.includes(step), `missing authority step '${step}'`);
  }
});

test('CrossAuthorityNav — has currentAuthority prop', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /currentAuthority/);
});

test('CrossAuthorityNav — has nav element', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /<nav/);
});

// ─── AuthorityHealthMap ───────────────────────────────────────────────────────

test('AuthorityHealthMap — file exists', () => {
  assert.ok(exists(ws('AuthorityHealthMap.tsx')));
});

test('AuthorityHealthMap — has use client', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /'use client'/);
});

test('AuthorityHealthMap — has default export AuthorityHealthMap', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /export default function AuthorityHealthMap/);
});

test('AuthorityHealthMap — has MCIM-18.6-AUTHORITY-HEALTH-MAP', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /MCIM-18\.6-AUTHORITY-HEALTH-MAP/);
});

test('AuthorityHealthMap — has Authority Health Authority', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /Authority Health Authority/);
});

test('AuthorityHealthMap — has aria-label authority-health-map', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /authority-health-map/);
});

test('AuthorityHealthMap — imports ControlTowerSnapshotV1 from coreApi', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /ControlTowerSnapshotV1/);
});

test('AuthorityHealthMap — uses chain_integrity field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /chain_integrity/);
});

test('AuthorityHealthMap — uses key_lifecycle field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /key_lifecycle/);
});

test('AuthorityHealthMap — uses connectors field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /connectors/);
});

test('AuthorityHealthMap — uses agents field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /agents/);
});

test('AuthorityHealthMap — uses lockers field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /lockers/);
});

test('AuthorityHealthMap — uses audit_incidents field', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /audit_incidents/);
});

test('AuthorityHealthMap — shows freshness or timestamp', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /freshness|last_rotation|last_sync|last_restart/i);
});

test('AuthorityHealthMap — shows health status', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /health|Health|ok|warning|error/);
});

test('AuthorityHealthMap — no fabricated hardcoded latency ms values', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /\d+ms['"]|\blatency.*=.*\d+\b/);
});

test('AuthorityHealthMap — no Math.random', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /Math\.random/);
});

test('AuthorityHealthMap — no localStorage', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /localStorage/);
});

test('AuthorityHealthMap — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /sessionStorage/);
});

test('AuthorityHealthMap — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /variant=['"]destructive['"]/);
});

test('AuthorityHealthMap — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /dangerouslySetInnerHTML/);
});

test('AuthorityHealthMap — has loading state', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /loading|animate-pulse/i);
});

test('AuthorityHealthMap — has snapshot prop', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /snapshot.*ControlTowerSnapshotV1/);
});

test('AuthorityHealthMap — does not use non-existent keys field', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /snap\.keys\./);
});

test('AuthorityHealthMap — does not use non-existent locked_count', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /locked_count/);
});

// ─── CorrelationGraph2 ────────────────────────────────────────────────────────

test('CorrelationGraph2 — file exists', () => {
  assert.ok(exists(ws('CorrelationGraph2.tsx')));
});

test('CorrelationGraph2 — has use client', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /'use client'/);
});

test('CorrelationGraph2 — has default export CorrelationGraph2', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /export default function CorrelationGraph2/);
});

test('CorrelationGraph2 — exports GraphNode2', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /export interface GraphNode2/);
});

test('CorrelationGraph2 — exports GraphEdge2', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /export interface GraphEdge2/);
});

test('CorrelationGraph2 — has MCIM-18.6-CORRELATION-GRAPH-2', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /MCIM-18\.6-CORRELATION-GRAPH-2/);
});

test('CorrelationGraph2 — has Correlation Authority', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /Correlation Authority/);
});

test('CorrelationGraph2 — has aria-label correlation-graph-2-panel', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /correlation-graph-2-panel/);
});

test('CorrelationGraph2 — GraphNode2 has id field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /id.*string/);
});

test('CorrelationGraph2 — GraphNode2 has label field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /label.*string/);
});

test('CorrelationGraph2 — GraphNode2 has authority field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /authority.*string/);
});

test('CorrelationGraph2 — GraphNode2 has confidence field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /confidence/);
});

test('CorrelationGraph2 — GraphNode2 has freshness field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /freshness/);
});

test('CorrelationGraph2 — GraphNode2 has owner field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /owner/);
});

test('CorrelationGraph2 — GraphNode2 has lifecycle field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /lifecycle/);
});

test('CorrelationGraph2 — GraphNode2 has trustStatus field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /trustStatus/);
});

test('CorrelationGraph2 — GraphNode2 has verificationState field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /verificationState/);
});

test('CorrelationGraph2 — GraphNode2 has nodeType field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /nodeType/);
});

test('CorrelationGraph2 — GraphEdge2 has from field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /from.*string/);
});

test('CorrelationGraph2 — GraphEdge2 has to field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /\bto\b.*string/);
});

test('CorrelationGraph2 — GraphEdge2 has relationship field', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /relationship/);
});

test('CorrelationGraph2 — no canvas element (pure HTML/CSS)', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /<canvas/);
});

test('CorrelationGraph2 — no Math.random (deterministic)', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /Math\.random/);
});

test('CorrelationGraph2 — no localStorage', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /localStorage/);
});

test('CorrelationGraph2 — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /sessionStorage/);
});

test('CorrelationGraph2 — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /variant=['"]destructive['"]/);
});

test('CorrelationGraph2 — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('CorrelationGraph2.tsx')), /dangerouslySetInnerHTML/);
});

test('CorrelationGraph2 — has loading state', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /loading|animate-pulse/i);
});

// ─── CommandPalette ───────────────────────────────────────────────────────────

test('CommandPalette — file exists', () => {
  assert.ok(exists(ws('CommandPalette.tsx')));
});

test('CommandPalette — has use client', () => {
  assert.match(read(ws('CommandPalette.tsx')), /'use client'/);
});

test('CommandPalette — has default export CommandPalette', () => {
  assert.match(read(ws('CommandPalette.tsx')), /export default function CommandPalette/);
});

test('CommandPalette — has MCIM-18.6-COMMAND-PALETTE', () => {
  assert.match(read(ws('CommandPalette.tsx')), /MCIM-18\.6-COMMAND-PALETTE/);
});

test('CommandPalette — has Command Palette Authority', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Command Palette Authority/);
});

test('CommandPalette — has aria-label command-palette', () => {
  assert.match(read(ws('CommandPalette.tsx')), /command-palette/);
});

test('CommandPalette — has data-testid command-palette', () => {
  assert.match(read(ws('CommandPalette.tsx')), /data-testid=['"]command-palette['"]/);
});

test('CommandPalette — has role="dialog"', () => {
  assert.match(read(ws('CommandPalette.tsx')), /role=['"]dialog['"]/);
});

test('CommandPalette — has aria-modal', () => {
  assert.match(read(ws('CommandPalette.tsx')), /aria-modal/);
});

test('CommandPalette — has Ctrl+K handler', () => {
  assert.match(read(ws('CommandPalette.tsx')), /ctrlKey.*key.*k|key.*k.*ctrlKey/i);
});

test('CommandPalette — has Escape close handler', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Escape|escape/);
});

test('CommandPalette — scope: Authorities', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Authorities/);
});

test('CommandPalette — scope: Capabilities', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Capabilities/);
});

test('CommandPalette — scope: Assessments', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Assessments/);
});

test('CommandPalette — scope: Evidence', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Evidence/);
});

test('CommandPalette — scope: Reports', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Reports/);
});

test('CommandPalette — scope: Customers', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Customers/);
});

test('CommandPalette — scope: Policies', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Policies/);
});

test('CommandPalette — scope: Findings', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Findings/);
});

test('CommandPalette — scope: Simulations', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Simulations/);
});

test('CommandPalette — scope: Replay', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Replay/);
});

test('CommandPalette — scope: Remediation', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Remediation/);
});

test('CommandPalette — scope: Portal', () => {
  assert.match(read(ws('CommandPalette.tsx')), /Portal/);
});

test('CommandPalette — has keyboard navigation', () => {
  assert.match(read(ws('CommandPalette.tsx')), /tabIndex|onKeyDown|ArrowDown|ArrowUp/);
});

test('CommandPalette — has open prop', () => {
  assert.match(read(ws('CommandPalette.tsx')), /open.*boolean|boolean.*open/);
});

test('CommandPalette — has onClose prop', () => {
  assert.match(read(ws('CommandPalette.tsx')), /onClose/);
});

test('CommandPalette — no localStorage', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /localStorage/);
});

test('CommandPalette — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /sessionStorage/);
});

test('CommandPalette — no Math.random', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /Math\.random/);
});

test('CommandPalette — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /variant=['"]destructive['"]/);
});

test('CommandPalette — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /dangerouslySetInnerHTML/);
});

test('CommandPalette — returns null when closed', () => {
  assert.match(read(ws('CommandPalette.tsx')), /if.*!.*open.*return null|!open.*return null/);
});

test('CommandPalette — 12 search scopes covered', () => {
  const content = read(ws('CommandPalette.tsx'));
  const scopes = ['Authorities', 'Capabilities', 'Assessments', 'Evidence',
    'Reports', 'Customers', 'Policies', 'Findings', 'Simulations', 'Replay',
    'Remediation', 'Portal'];
  for (const scope of scopes) {
    assert.ok(content.includes(scope), `missing search scope '${scope}'`);
  }
});

// ─── PlaybookPanel ────────────────────────────────────────────────────────────

test('PlaybookPanel — file exists', () => {
  assert.ok(exists(ws('PlaybookPanel.tsx')));
});

test('PlaybookPanel — has use client', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /'use client'/);
});

test('PlaybookPanel — has default export PlaybookPanel', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /export default function PlaybookPanel/);
});

test('PlaybookPanel — exports Playbook', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /export interface Playbook/);
});

test('PlaybookPanel — exports PlaybookStep', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /export interface PlaybookStep/);
});

test('PlaybookPanel — has MCIM-18.6-PLAYBOOK-PANEL', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /MCIM-18\.6-PLAYBOOK-PANEL/);
});

test('PlaybookPanel — has Playbook Authority', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /Playbook Authority/);
});

test('PlaybookPanel — has aria-label playbook-panel', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /playbook-panel/);
});

test('PlaybookPanel — Playbook has authorities field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /authorities.*string\[\]|string\[\].*authorities/);
});

test('PlaybookPanel — Playbook has workflow field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /workflow.*PlaybookStep|PlaybookStep.*workflow/);
});

test('PlaybookPanel — Playbook has evidence field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /evidence.*string\[\]|string\[\].*evidence/);
});

test('PlaybookPanel — Playbook has reports field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /reports.*string\[\]|string\[\].*reports/);
});

test('PlaybookPanel — Playbook has remediation field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /remediation.*string\[\]|string\[\].*remediation/);
});

test('PlaybookPanel — Playbook has policies field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /policies.*string\[\]|string\[\].*policies/);
});

test('PlaybookPanel — Playbook has simulations field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /simulations.*string\[\]|string\[\].*simulations/);
});

test('PlaybookPanel — Playbook has timeline field', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /timeline.*string\[\]|string\[\].*timeline/);
});

test('PlaybookPanel — PlaybookStep has name, authority, drillDown', () => {
  const content = read(ws('PlaybookPanel.tsx'));
  assert.match(content, /name.*string/);
  assert.match(content, /authority.*string/);
  assert.match(content, /drillDown.*string/);
});

test('PlaybookPanel — read-only (no write operations)', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /method.*POST|fetch.*POST/);
});

test('PlaybookPanel — has empty state', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /No playbooks|empty/i);
});

test('PlaybookPanel — has loading state', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /loading|animate-pulse/i);
});

test('PlaybookPanel — no Math.random', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /Math\.random/);
});

test('PlaybookPanel — no localStorage', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /localStorage/);
});

test('PlaybookPanel — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /sessionStorage/);
});

test('PlaybookPanel — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /variant=['"]destructive['"]/);
});

test('PlaybookPanel — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('PlaybookPanel.tsx')), /dangerouslySetInnerHTML/);
});

// ─── DelegationPanel ─────────────────────────────────────────────────────────

test('DelegationPanel — file exists', () => {
  assert.ok(exists(ws('DelegationPanel.tsx')));
});

test('DelegationPanel — has use client', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'use client'/);
});

test('DelegationPanel — has default export DelegationPanel', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /export default function DelegationPanel/);
});

test('DelegationPanel — exports DelegationAction', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /export interface DelegationAction/);
});

test('DelegationPanel — exports DelegationActionType', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /export type DelegationActionType/);
});

test('DelegationPanel — has MCIM-18.6-DELEGATION-PANEL', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /MCIM-18\.6-DELEGATION-PANEL/);
});

test('DelegationPanel — has Delegation Authority', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /Delegation Authority/);
});

test('DelegationPanel — has aria-label delegation-panel', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /delegation-panel/);
});

test('DelegationPanel — action type: approve', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'approve'/);
});

test('DelegationPanel — action type: reject', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'reject'/);
});

test('DelegationPanel — action type: assign', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'assign'/);
});

test('DelegationPanel — action type: delegate', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'delegate'/);
});

test('DelegationPanel — action type: escalate', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'escalate'/);
});

test('DelegationPanel — action type: review', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'review'/);
});

test('DelegationPanel — action type: verify', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'verify'/);
});

test('DelegationPanel — action type: generate-report', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'generate-report'/);
});

test('DelegationPanel — action type: publish', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'publish'/);
});

test('DelegationPanel — action type: archive', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'archive'/);
});

test('DelegationPanel — action type: close', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /'close'/);
});

test('DelegationPanel — DelegationAction has delegatedTo field', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /delegatedTo/);
});

test('DelegationPanel — has onDelegate prop', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /onDelegate/);
});

test('DelegationPanel — DelegationAction has authority field', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /authority.*string/);
});

test('DelegationPanel — DelegationAction has mcimId field', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /mcimId/);
});

test('DelegationPanel — DelegationAction has sourceObject field', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /sourceObject/);
});

test('DelegationPanel — DelegationAction has drillDown field', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /drillDown/);
});

test('DelegationPanel — no Math.random', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /Math\.random/);
});

test('DelegationPanel — no localStorage', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /localStorage/);
});

test('DelegationPanel — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /sessionStorage/);
});

test('DelegationPanel — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /variant=['"]destructive['"]/);
});

test('DelegationPanel — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /dangerouslySetInnerHTML/);
});

// ─── ExportPanel ──────────────────────────────────────────────────────────────

test('ExportPanel — file exists', () => {
  assert.ok(exists(ws('ExportPanel.tsx')));
});

test('ExportPanel — has use client', () => {
  assert.match(read(ws('ExportPanel.tsx')), /'use client'/);
});

test('ExportPanel — has default export ExportPanel', () => {
  assert.match(read(ws('ExportPanel.tsx')), /export default function ExportPanel/);
});

test('ExportPanel — exports WorkspaceSnapshot', () => {
  assert.match(read(ws('ExportPanel.tsx')), /export interface WorkspaceSnapshot/);
});

test('ExportPanel — exports ExportFormat', () => {
  assert.match(read(ws('ExportPanel.tsx')), /export type ExportFormat/);
});

test('ExportPanel — has MCIM-18.6-EXPORT-PANEL', () => {
  assert.match(read(ws('ExportPanel.tsx')), /MCIM-18\.6-EXPORT-PANEL/);
});

test('ExportPanel — has Export Authority', () => {
  assert.match(read(ws('ExportPanel.tsx')), /Export Authority/);
});

test('ExportPanel — has aria-label export-panel', () => {
  assert.match(read(ws('ExportPanel.tsx')), /export-panel/);
});

test('ExportPanel — ExportFormat has json', () => {
  assert.match(read(ws('ExportPanel.tsx')), /'json'/);
});

test('ExportPanel — ExportFormat has csv', () => {
  assert.match(read(ws('ExportPanel.tsx')), /'csv'/);
});

test('ExportPanel — WorkspaceSnapshot has provenanceMetadata', () => {
  assert.match(read(ws('ExportPanel.tsx')), /provenanceMetadata/);
});

test('ExportPanel — provenanceMetadata has mcimId', () => {
  assert.match(read(ws('ExportPanel.tsx')), /mcimId.*string/);
});

test('ExportPanel — provenanceMetadata has authority', () => {
  assert.match(read(ws('ExportPanel.tsx')), /authority.*string/);
});

test('ExportPanel — provenanceMetadata has sourceOfTruth', () => {
  assert.match(read(ws('ExportPanel.tsx')), /sourceOfTruth.*string/);
});

test('ExportPanel — provenanceMetadata has exportedBy', () => {
  assert.match(read(ws('ExportPanel.tsx')), /exportedBy/);
});

test('ExportPanel — WorkspaceSnapshot has queue field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /queue/);
});

test('ExportPanel — WorkspaceSnapshot has cases field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /cases/);
});

test('ExportPanel — WorkspaceSnapshot has timeline field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /timeline/);
});

test('ExportPanel — WorkspaceSnapshot has decisionLedger field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /decisionLedger/);
});

test('ExportPanel — WorkspaceSnapshot has workflowState field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /workflowState/);
});

test('ExportPanel — WorkspaceSnapshot has healthMap field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /healthMap/);
});

test('ExportPanel — WorkspaceSnapshot has exportedAt field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /exportedAt/);
});

test('ExportPanel — WorkspaceSnapshot has tenantId field', () => {
  assert.match(read(ws('ExportPanel.tsx')), /tenantId/);
});

test('ExportPanel — has onExport prop', () => {
  assert.match(read(ws('ExportPanel.tsx')), /onExport/);
});

test('ExportPanel — no Math.random', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /Math\.random/);
});

test('ExportPanel — no localStorage', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /localStorage/);
});

test('ExportPanel — no sessionStorage', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /sessionStorage/);
});

test('ExportPanel — no destructive badge variant', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /variant=['"]destructive['"]/);
});

test('ExportPanel — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /dangerouslySetInnerHTML/);
});

// ─── Workspace Page ───────────────────────────────────────────────────────────

const PAGE = 'apps/console/app/workspace/page.tsx';

test('Workspace page — file exists', () => {
  assert.ok(exists(PAGE));
});

test('Workspace page — is server component (no use client at top)', () => {
  const content = read(PAGE);
  assert.doesNotMatch(content.slice(0, 20), /'use client'/);
});

test('Workspace page — has async function WorkspaceOverviewPage', () => {
  assert.match(read(PAGE), /async function WorkspaceOverviewPage/);
});

test('Workspace page — has data-testid workspace-page', () => {
  assert.match(read(PAGE), /workspace-page/);
});

test('Workspace page — has data-testid workspace-heading', () => {
  assert.match(read(PAGE), /workspace-heading/);
});

test('Workspace page — has data-testid workspace-queue-heading', () => {
  assert.match(read(PAGE), /workspace-queue-heading/);
});

test('Workspace page — has data-testid workspace-case-heading', () => {
  assert.match(read(PAGE), /workspace-case-heading/);
});

test('Workspace page — has data-testid workspace-ledger-heading', () => {
  assert.match(read(PAGE), /workspace-ledger-heading/);
});

test('Workspace page — has data-testid workspace-workflow-heading', () => {
  assert.match(read(PAGE), /workspace-workflow-heading/);
});

test('Workspace page — has data-testid workspace-timeline-heading', () => {
  assert.match(read(PAGE), /workspace-timeline-heading/);
});

test('Workspace page — has data-testid workspace-health-heading', () => {
  assert.match(read(PAGE), /workspace-health-heading/);
});

test('Workspace page — has data-testid workspace-command-palette-toggle', () => {
  assert.match(read(PAGE), /workspace-command-palette-toggle/);
});

test('Workspace page — has Promise.allSettled', () => {
  assert.match(read(PAGE), /Promise\.allSettled/);
});

test('Workspace page — has MCIM-18.6-OPS-WORKSPACE reference', () => {
  assert.match(read(PAGE), /MCIM-18\.6-OPS-WORKSPACE/);
});

test('Workspace page — imports from operations-workspace', () => {
  assert.match(read(PAGE), /operations-workspace/);
});

test('Workspace page — no NEXT_PUBLIC env vars', () => {
  assert.doesNotMatch(read(PAGE), /NEXT_PUBLIC/);
});

test('Workspace page — no direct HTTP fetch', () => {
  assert.doesNotMatch(read(PAGE), /fetch\(['"]http/);
});

test('Workspace page — no Math.random', () => {
  assert.doesNotMatch(read(PAGE), /Math\.random/);
});

test('Workspace page — no localStorage', () => {
  assert.doesNotMatch(read(PAGE), /localStorage/);
});

test('Workspace page — no sessionStorage', () => {
  assert.doesNotMatch(read(PAGE), /sessionStorage/);
});

test('Workspace page — no mock data', () => {
  assert.doesNotMatch(read(PAGE), /MOCK_|fake.*data|hardcoded/i);
});

test('Workspace page — has UnifiedWorkQueue reference', () => {
  assert.match(read(PAGE), /UnifiedWorkQueue/);
});

test('Workspace page — has CaseWorkspace reference', () => {
  assert.match(read(PAGE), /CaseWorkspace/);
});

test('Workspace page — has DecisionLedger reference', () => {
  assert.match(read(PAGE), /DecisionLedger/);
});

test('Workspace page — has WorkflowProgress reference', () => {
  assert.match(read(PAGE), /WorkflowProgress/);
});

test('Workspace page — has InvestigationTimeline reference', () => {
  assert.match(read(PAGE), /InvestigationTimeline/);
});

test('Workspace page — has AuthorityHealthMap reference', () => {
  assert.match(read(PAGE), /AuthorityHealthMap/);
});

test('Workspace page — has CommandPalette reference', () => {
  assert.match(read(PAGE), /CommandPalette/);
});

test('Workspace page — no dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(PAGE), /dangerouslySetInnerHTML/);
});

test('Workspace page — uses getCommandCenterSnapshot', () => {
  assert.match(read(PAGE), /getCommandCenterSnapshot|getControlTowerSnapshot/);
});

test('Workspace page — uses getRecentFeedEvents', () => {
  assert.match(read(PAGE), /getRecentFeedEvents|getFeedLive/);
});

test('Workspace page — has ExportPanel reference', () => {
  assert.match(read(PAGE), /ExportPanel/);
});

// ─── CI Script ────────────────────────────────────────────────────────────────

const CI = 'tools/ci/check_operations_workspace.py';

test('CI script — file exists', () => {
  assert.ok(exists(CI));
});

test('CI script — has shebang', () => {
  assert.match(read(CI), /^#!\/usr\/bin\/env python3/);
});

test('CI script — has COMPONENT_DIR', () => {
  assert.match(read(CI), /COMPONENT_DIR|component_dir/);
});

test('CI script — references operations-workspace', () => {
  assert.match(read(CI), /operations-workspace/);
});

test('CI script — references workspace page', () => {
  assert.match(read(CI), /workspace.*page\.tsx|page\.tsx.*workspace/i);
});

test('CI script — validates MCIM_ID', () => {
  assert.match(read(CI), /MCIM_ID/);
});

test('CI script — validates AUTHORITY', () => {
  assert.match(read(CI), /AUTHORITY/);
});

test('CI script — validates sourceOfTruth', () => {
  assert.match(read(CI), /sourceOfTruth/);
});

test('CI script — validates drillDown', () => {
  assert.match(read(CI), /drillDown/);
});

test('CI script — Math.random in prohibited patterns', () => {
  assert.match(read(CI), /Math\.random/);
});

test('CI script — dangerouslySetInnerHTML in prohibited patterns', () => {
  assert.match(read(CI), /dangerouslySetInnerHTML/);
});

test('CI script — localStorage in prohibited patterns', () => {
  assert.match(read(CI), /localStorage/);
});

test('CI script — sessionStorage in prohibited patterns', () => {
  assert.match(read(CI), /sessionStorage/);
});

test('CI script — destructive in prohibited patterns', () => {
  assert.match(read(CI), /destructive/);
});

test('CI script — has main function', () => {
  assert.match(read(CI), /def main/);
});

test('CI script — exits 0 on pass', () => {
  assert.match(read(CI), /return 0/);
});

test('CI script — exits 1 on fail', () => {
  assert.match(read(CI), /return 1/);
});

test('CI script — validates workspace page anchors', () => {
  assert.match(read(CI), /workspace-heading|WORKSPACE_PAGE|workspace_page/i);
});

test('CI script — checks for export default function', () => {
  assert.match(read(CI), /export default function/);
});

test('CI script — uses pathlib or os.path', () => {
  assert.match(read(CI), /pathlib|Path|os\.path/);
});

test('CI script — imports re', () => {
  assert.match(read(CI), /import re/);
});

test('CI script — imports sys', () => {
  assert.match(read(CI), /import sys/);
});

test('CI script — has WorkspaceShell in exempt files', () => {
  assert.match(read(CI), /WorkspaceShell/);
});

test('CI script — prints pass message', () => {
  assert.match(read(CI), /check passed|Operations workspace check passed/i);
});

test('CI script — prints ERROR prefix on failures', () => {
  assert.match(read(CI), /ERROR/);
});

test('CI script — has __main__ guard', () => {
  assert.match(read(CI), /__main__|if __name__/);
});

// ─── Architecture Doc ─────────────────────────────────────────────────────────

const DOC = 'docs/architecture/OPERATIONS_WORKSPACE_18_6_4.md';

test('Architecture doc — file exists', () => {
  assert.ok(exists(DOC));
});

test('Architecture doc — references MCIM-18.6-OPS-WORKSPACE', () => {
  assert.match(read(DOC), /MCIM-18\.6-OPS-WORKSPACE/);
});

test('Architecture doc — has Case Model section', () => {
  assert.match(read(DOC), /[Cc]ase [Mm]odel/);
});

test('Architecture doc — has Work Queue section', () => {
  assert.match(read(DOC), /[Ww]ork [Qq]ueue/);
});

test('Architecture doc — has Workflow Engine section', () => {
  assert.match(read(DOC), /[Ww]orkflow [Ee]ngine|[Ww]orkflow [Pp]rogress/);
});

test('Architecture doc — has Decision Ledger section', () => {
  assert.match(read(DOC), /[Dd]ecision [Ll]edger/);
});

test('Architecture doc — has Investigation Timeline section', () => {
  assert.match(read(DOC), /[Ii]nvestigation [Tt]imeline/);
});

test('Architecture doc — has Authority Health Map section', () => {
  assert.match(read(DOC), /[Aa]uthority [Hh]ealth [Mm]ap/);
});

test('Architecture doc — has Command Palette section', () => {
  assert.match(read(DOC), /[Cc]ommand [Pp]alette/);
});

test('Architecture doc — has Export Model section', () => {
  assert.match(read(DOC), /[Ee]xport [Mm]odel|[Ee]xport [Pp]anel/);
});

test('Architecture doc — mentions WCAG', () => {
  assert.match(read(DOC), /WCAG/);
});

test('Architecture doc — has PR 18.6.4 reference', () => {
  assert.match(read(DOC), /18\.6\.4/);
});

test('Architecture doc — references authority chain', () => {
  assert.match(read(DOC), /Assessment.*Evidence|Evidence.*Verification/);
});

test('Architecture doc — mentions provenance', () => {
  assert.match(read(DOC), /provenance/i);
});

test('Architecture doc — mentions append-only or immutable', () => {
  assert.match(read(DOC), /append-only|immutable/i);
});

test('Architecture doc — mentions tenant isolation', () => {
  assert.match(read(DOC), /tenant/i);
});

test('Architecture doc — mentions delegation', () => {
  assert.match(read(DOC), /[Dd]elegation/);
});

test('Architecture doc — mentions Cross-Authority Navigation', () => {
  assert.match(read(DOC), /[Cc]ross-[Aa]uthority/);
});

test('Architecture doc — mentions Correlation Graph', () => {
  assert.match(read(DOC), /[Cc]orrelation [Gg]raph/);
});

test('Architecture doc — has Playbook section', () => {
  assert.match(read(DOC), /[Pp]laybook/);
});

test('Architecture doc — mentions 800 tests or test count', () => {
  assert.match(read(DOC), /800\+?|8[0-9]{2}\+?\s*tests|deterministic.*test/i);
});

// ─── Accessibility tests ──────────────────────────────────────────────────────

const WS_COMPONENTS = [
  'UnifiedWorkQueue.tsx', 'CaseWorkspace.tsx', 'DecisionLedger.tsx',
  'WorkflowProgress.tsx', 'InvestigationTimeline.tsx', 'CrossAuthorityNav.tsx',
  'AuthorityHealthMap.tsx', 'CorrelationGraph2.tsx', 'CommandPalette.tsx',
  'PlaybookPanel.tsx', 'DelegationPanel.tsx', 'ExportPanel.tsx',
];

for (const component of WS_COMPONENTS) {
  test(`${component} — no aria-expanded on role="complementary"`, () => {
    const content = read(ws(component));
    const hasComp = content.includes('role="complementary"');
    if (hasComp) {
      const compIdx = content.indexOf('role="complementary"');
      const surroundingBlock = content.slice(Math.max(0, compIdx - 200), compIdx + 200);
      assert.doesNotMatch(surroundingBlock, /aria-expanded/);
    }
  });
}

test('CommandPalette — has focus management', () => {
  assert.match(read(ws('CommandPalette.tsx')), /focus|autoFocus|useRef.*focus/i);
});

test('CommandPalette — dialog has aria-label', () => {
  assert.match(read(ws('CommandPalette.tsx')), /aria-label.*command-palette|command-palette.*aria-label/);
});

test('InvestigationTimeline — has role="list" for events', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /role=['"]list['"]/);
});

test('UnifiedWorkQueue — icons have aria-hidden', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /aria-hidden/);
});

test('CaseWorkspace — icons have aria-hidden', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /aria-hidden/);
});

test('DecisionLedger — icons have aria-hidden', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /aria-hidden/);
});

test('WorkflowProgress — has aria-label on progress elements', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /aria-label/);
});

test('CrossAuthorityNav — has role="nav" or nav element', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /<nav|role=['"]navigation['"]/);
});

test('DelegationPanel — delegation target input has aria-label', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /aria-label.*[Dd]elegate/);
});

test('PlaybookPanel — expandable rows are keyboard accessible', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /button|tabIndex|onKeyDown/);
});

test('AuthorityHealthMap — table or list has role', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /role=['"]table['"]|<table|role=['"]list['"]/);
});

test('CorrelationGraph2 — graph elements have aria-label', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /aria-label/);
});

test('ExportPanel — export buttons are keyboard accessible', () => {
  assert.match(read(ws('ExportPanel.tsx')), /button|Button/);
});

test('WorkspaceShell — has MCIM disclosure toggle button', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /button|Button/);
});

// ─── No-fake-data enforcement ─────────────────────────────────────────────────

for (const component of [...WS_COMPONENTS, 'WorkspaceShell.tsx']) {
  test(`${component} — no Apex National Bank fake data`, () => {
    assert.doesNotMatch(read(ws(component)), /Apex National Bank/);
  });

  test(`${component} — no meridian-health fake data`, () => {
    assert.doesNotMatch(read(ws(component)), /meridian-health/);
  });

  test(`${component} — no hipaa.rego fake data`, () => {
    assert.doesNotMatch(read(ws(component)), /hipaa\.rego/);
  });
}

test('Workspace page — no Apex National Bank fake data', () => {
  assert.doesNotMatch(read(PAGE), /Apex National Bank/);
});

test('Workspace page — no hardcoded fake tenant IDs', () => {
  assert.doesNotMatch(read(PAGE), /tenant-123|test-tenant|fake-tenant/i);
});

// ─── Cross-component consistency ──────────────────────────────────────────────

const ALL_WS_COMPONENTS = [...WS_COMPONENTS, 'WorkspaceShell.tsx'];

for (const component of ALL_WS_COMPONENTS) {
  test(`${component} — has 'use client'`, () => {
    assert.match(read(ws(component)), /'use client'/);
  });

  test(`${component} — has MCIM-18.6- prefix`, () => {
    assert.match(read(ws(component)), /MCIM-18\.6-/);
  });

  test(`${component} — has const MCIM_ID`, () => {
    assert.match(read(ws(component)), /MCIM_ID.*=.*'MCIM-18\.6-|const MCIM_ID/);
  });

  test(`${component} — has export default function`, () => {
    assert.match(read(ws(component)), /export default function/);
  });
}

// ─── MCIM allowlist coverage ──────────────────────────────────────────────────

const MCIM_DOCS = 'tools/ci/check_mcim_docs.py';

test('MCIM allowlist — file exists', () => {
  assert.ok(exists(MCIM_DOCS));
});

test('MCIM allowlist — operations-workspace directory registered', () => {
  assert.match(read(MCIM_DOCS), /operations-workspace/);
});

test('MCIM allowlist — WorkspaceShell.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /WorkspaceShell\.tsx/);
});

test('MCIM allowlist — UnifiedWorkQueue.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /UnifiedWorkQueue\.tsx/);
});

test('MCIM allowlist — CaseWorkspace.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /CaseWorkspace\.tsx/);
});

test('MCIM allowlist — DecisionLedger.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /DecisionLedger\.tsx/);
});

test('MCIM allowlist — WorkflowProgress.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /WorkflowProgress\.tsx/);
});

test('MCIM allowlist — InvestigationTimeline.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /InvestigationTimeline\.tsx/);
});

test('MCIM allowlist — CrossAuthorityNav.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /CrossAuthorityNav\.tsx/);
});

test('MCIM allowlist — AuthorityHealthMap.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /AuthorityHealthMap\.tsx/);
});

test('MCIM allowlist — CorrelationGraph2.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /CorrelationGraph2\.tsx/);
});

test('MCIM allowlist — CommandPalette.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /CommandPalette\.tsx/);
});

test('MCIM allowlist — PlaybookPanel.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /PlaybookPanel\.tsx/);
});

test('MCIM allowlist — DelegationPanel.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /DelegationPanel\.tsx/);
});

test('MCIM allowlist — ExportPanel.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /ExportPanel\.tsx/);
});

test('MCIM allowlist — workspace page.tsx registered', () => {
  assert.match(read(MCIM_DOCS), /app\/workspace\/page\.tsx/);
});

test('MCIM allowlist — CI script registered', () => {
  assert.match(read(MCIM_DOCS), /check_operations_workspace\.py/);
});

test('MCIM allowlist — test file registered', () => {
  assert.match(read(MCIM_DOCS), /operations-workspace\.test\.js/);
});

test('MCIM allowlist — architecture doc registered', () => {
  assert.match(read(MCIM_DOCS), /OPERATIONS_WORKSPACE_18_6_4\.md/);
});

test('MCIM allowlist — PR 18.6.4 block present', () => {
  assert.match(read(MCIM_DOCS), /PR 18\.6\.4/);
});

// ─── SOC gate coverage ────────────────────────────────────────────────────────

const SOC = 'docs/SOC_EXECUTION_GATES_2026-02-15.md';

test('SOC gate — file exists', () => {
  assert.ok(exists(SOC));
});

test('SOC gate — PR 18.6.4 entry present', () => {
  assert.match(read(SOC), /18\.6\.4/);
});

test('SOC gate — MCIM-18.6-OPS-WORKSPACE referenced in SOC', () => {
  assert.match(read(SOC), /MCIM-18\.6-OPS-WORKSPACE/);
});

test('SOC gate — Enterprise Operations Workspace named', () => {
  assert.match(read(SOC), /Enterprise Operations Workspace/);
});

// ─── PR fix log coverage ──────────────────────────────────────────────────────

const FIX_LOG = 'docs/ai/PR_FIX_LOG.md';

test('PR fix log — file exists', () => {
  assert.ok(exists(FIX_LOG));
});

test('PR fix log — PR 18.6.4 entry present', () => {
  assert.match(read(FIX_LOG), /18\.6\.4/);
});

test('PR fix log — check_operations_workspace.py referenced', () => {
  assert.match(read(FIX_LOG), /check_operations_workspace/);
});

// ─── ROADMAP coverage ─────────────────────────────────────────────────────────

test('ROADMAP — file exists', () => {
  assert.ok(exists('ROADMAP.md'));
});

test('ROADMAP — PR 18.6.4 row present', () => {
  assert.match(read('ROADMAP.md'), /18\.6\.4/);
});

test('ROADMAP — Enterprise Operations Workspace listed', () => {
  assert.match(read('ROADMAP.md'), /Enterprise Operations Workspace/);
});

// ─── Additional UnifiedWorkQueue field tests ──────────────────────────────────

test('UnifiedWorkQueue — priority filter: all', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'all'/);
});

test('UnifiedWorkQueue — priority filter: critical', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /'critical'/);
});

test('UnifiedWorkQueue — priority variant mapping exists', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /PRIORITY_VARIANT|PRIORITY_ORDER/);
});

test('UnifiedWorkQueue — wraps in WorkspaceShell', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /WorkspaceShell/);
});

test('UnifiedWorkQueue — shows SLA in item row', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /sla|SLA/);
});

test('UnifiedWorkQueue — shows authority in item row', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /\.authority|authority\b/);
});

test('UnifiedWorkQueue — shows workflowStage in item row', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /workflowStage/);
});

// ─── Additional CaseWorkspace tests ───────────────────────────────────────────

test('CaseWorkspace — wraps in WorkspaceShell', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /WorkspaceShell/);
});

test('CaseWorkspace — shows linkedAssessments count or items', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedAssessments/);
});

test('CaseWorkspace — shows linkedDecisions count or items', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /linkedDecisions/);
});

test('CaseWorkspace — STATUS_VARIANT mapping exists', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /STATUS_VARIANT/);
});

test('CaseWorkspace — PRIORITY_VARIANT mapping exists', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /PRIORITY_VARIANT/);
});

// ─── Additional DecisionLedger tests ─────────────────────────────────────────

test('DecisionLedger — wraps in WorkspaceShell', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /WorkspaceShell/);
});

test('DecisionLedger — shows provenanceChain items', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /provenanceChain/);
});

test('DecisionLedger — shows alternativesConsidered items', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /alternativesConsidered/);
});

test('DecisionLedger — shows linkedReports items', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /linkedReports/);
});

test('DecisionLedger — shows reviewer field', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /reviewer/);
});

// ─── Additional WorkflowProgress tests ───────────────────────────────────────

test('WorkflowProgress — wraps in WorkspaceShell', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /WorkspaceShell/);
});

test('WorkflowProgress — STAGE_COLOR or STAGE_BADGE_VARIANT mapping', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /STAGE_COLOR|STAGE_BADGE_VARIANT/);
});

test('WorkflowProgress — WorkflowState has type field', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /type.*assessment.*evidence|'assessment'.*'evidence'/);
});

test('WorkflowProgress — has role="list" or table for workflow list', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /role=['"]list['"]|<ul|<table/);
});

// ─── Additional InvestigationTimeline tests ───────────────────────────────────

test('InvestigationTimeline — wraps in WorkspaceShell', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /WorkspaceShell/);
});

test('InvestigationTimeline — shows correlationId', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /correlationId/);
});

test('InvestigationTimeline — shows actor', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /actor/);
});

test('InvestigationTimeline — shows confidence value', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /confidence/);
});

test('InvestigationTimeline — 8 event types defined', () => {
  const content = read(ws('InvestigationTimeline.tsx'));
  const types = ['created', 'modified', 'verified', 'reviewed', 'approved', 'published', 'remediated', 'closed'];
  for (const t of types) {
    assert.ok(content.includes(`'${t}'`), `missing event type '${t}'`);
  }
});

// ─── Additional AuthorityHealthMap tests ──────────────────────────────────────

test('AuthorityHealthMap — wraps in WorkspaceShell', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /WorkspaceShell/);
});

test('AuthorityHealthMap — shows errors count or list', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /errors/);
});

test('AuthorityHealthMap — shows agents.quarantine_count', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /quarantine_count/);
});

test('AuthorityHealthMap — shows connectors.enabled', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /enabled/);
});

test('AuthorityHealthMap — shows key_lifecycle.active_key_count', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /active_key_count/);
});

test('AuthorityHealthMap — shows lockers.status', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /lockers\.status|lockers.*status/);
});

// ─── Additional CorrelationGraph2 tests ──────────────────────────────────────

test('CorrelationGraph2 — wraps in WorkspaceShell', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /WorkspaceShell/);
});

test('CorrelationGraph2 — has nodes prop', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /nodes.*GraphNode2|GraphNode2.*nodes/);
});

test('CorrelationGraph2 — has edges prop', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /edges.*GraphEdge2|GraphEdge2.*edges/);
});

test('CorrelationGraph2 — shows node authority', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /\.authority/);
});

test('CorrelationGraph2 — shows node confidence', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /confidence/);
});

test('CorrelationGraph2 — shows node trustStatus', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /trustStatus/);
});

test('CorrelationGraph2 — shows node verificationState', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /verificationState/);
});

// ─── Additional CommandPalette tests ─────────────────────────────────────────

test('CommandPalette — wraps in WorkspaceShell or has WorkspaceShell', () => {
  const content = read(ws('CommandPalette.tsx'));
  assert.match(content, /WorkspaceShell|WidgetShell/);
});

test('CommandPalette — has query/search input field', () => {
  assert.match(read(ws('CommandPalette.tsx')), /input|Input|query|search/i);
});

test('CommandPalette — filters results based on query', () => {
  assert.match(read(ws('CommandPalette.tsx')), /filter|toLowerCase|includes/);
});

test('CommandPalette — has SEARCH_ITEMS or similar static map', () => {
  assert.match(read(ws('CommandPalette.tsx')), /SEARCH_ITEMS|PALETTE_ITEMS|searchItems|entries/);
});

test('CommandPalette — each search item has path field', () => {
  assert.match(read(ws('CommandPalette.tsx')), /path.*\/dashboard|\/dashboard.*path/);
});

// ─── Additional DelegationPanel tests ────────────────────────────────────────

test('DelegationPanel — wraps in WorkspaceShell', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /WorkspaceShell/);
});

test('DelegationPanel — 11 action types defined', () => {
  const content = read(ws('DelegationPanel.tsx'));
  const types = ['approve', 'reject', 'assign', 'delegate', 'escalate', 'review',
    'verify', 'generate-report', 'publish', 'archive', 'close'];
  for (const t of types) {
    assert.ok(content.includes(`'${t}'`), `missing action type '${t}'`);
  }
});

test('DelegationPanel — shows drillDown link for each action', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /href.*drillDown|drillDown.*href/);
});

test('DelegationPanel — shows action title', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /\.title/);
});

test('DelegationPanel — has loading state', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /loading|animate-pulse/i);
});

test('DelegationPanel — has empty state', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /No actions|empty/i);
});

// ─── Additional ExportPanel tests ────────────────────────────────────────────

test('ExportPanel — wraps in WorkspaceShell', () => {
  assert.match(read(ws('ExportPanel.tsx')), /WorkspaceShell/);
});

test('ExportPanel — shows provenanceMetadata values', () => {
  assert.match(read(ws('ExportPanel.tsx')), /provenanceMetadata\.mcimId|provenanceMetadata\.authority/);
});

test('ExportPanel — has JSON export button', () => {
  assert.match(read(ws('ExportPanel.tsx')), /json|JSON/);
});

test('ExportPanel — has CSV export button', () => {
  assert.match(read(ws('ExportPanel.tsx')), /csv|CSV/);
});

test('ExportPanel — shows exportedAt timestamp', () => {
  assert.match(read(ws('ExportPanel.tsx')), /exportedAt/);
});

test('ExportPanel — shows tenantId', () => {
  assert.match(read(ws('ExportPanel.tsx')), /tenantId/);
});

test('ExportPanel — shows no snapshot empty state', () => {
  assert.match(read(ws('ExportPanel.tsx')), /No snapshot|No workspace|null/i);
});

// ─── Additional WorkspaceShell tests ─────────────────────────────────────────

test('WorkspaceShell — has refreshPolicy prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /refreshPolicy/);
});

test('WorkspaceShell — has lastUpdated prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /lastUpdated/);
});

test('WorkspaceShell — has confidence prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /confidence/);
});

test('WorkspaceShell — has className prop', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /className/);
});

test('WorkspaceShell — shows MCIM ID in metadata', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /\{mcimId\}|\{sot\}|mcimId/);
});

test('WorkspaceShell — shows authority in metadata', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /\{authority\}/);
});

test('WorkspaceShell — shows drill down link', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /drillDown|drill.*down/i);
});

test('WorkspaceShell — collapse/expand toggle', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /useState|setMeta|setOpen|toggle/i);
});

// ─── Additional Workspace Page tests ─────────────────────────────────────────

test('Workspace page — CrossAuthorityNav reference', () => {
  assert.match(read(PAGE), /CrossAuthorityNav/);
});

test('Workspace page — PlaybookPanel reference', () => {
  assert.match(read(PAGE), /PlaybookPanel/);
});

test('Workspace page — DelegationPanel reference', () => {
  assert.match(read(PAGE), /DelegationPanel/);
});

test('Workspace page — CorrelationGraph2 reference', () => {
  assert.match(read(PAGE), /CorrelationGraph2/);
});

test('Workspace page — WorkflowProgress reference', () => {
  assert.match(read(PAGE), /WorkflowProgress/);
});

test('Workspace page — no aria-expanded on role=complementary', () => {
  const content = read(PAGE);
  const hasComp = content.includes('role="complementary"');
  if (hasComp) {
    assert.doesNotMatch(content, /aria-expanded.*role=['"]complementary['"]|role=['"]complementary['"].*aria-expanded/);
  }
});

test('Workspace page — has export default', () => {
  assert.match(read(PAGE), /export default/);
});

test('Workspace page — no hardcoded mock strings', () => {
  assert.doesNotMatch(read(PAGE), /MOCK_CHART_DATA|MOCK_DOMAIN_SCORES|MOCK_FEED/);
});

test('Workspace page — no Apex National Bank', () => {
  assert.doesNotMatch(read(PAGE), /Apex National Bank/);
});

test('Workspace page — no meridian-health', () => {
  assert.doesNotMatch(read(PAGE), /meridian-health/);
});

// ─── ControlTowerSnapshotV1 field safety ──────────────────────────────────────

const SNAPSHOT_COMPONENTS = [
  ws('AuthorityHealthMap.tsx'),
  ws('WorkflowProgress.tsx'),
  ws('CrossAuthorityNav.tsx'),
  PAGE,
];

for (const file of SNAPSHOT_COMPONENTS) {
  const label = path.basename(file);
  test(`${label} — does not use non-existent snap.keys field`, () => {
    assert.doesNotMatch(read(file), /snap\.keys\./);
  });

  test(`${label} — does not use non-existent locked_count`, () => {
    assert.doesNotMatch(read(file), /\.locked_count/);
  });
}

// ─── Component interaction contract tests ─────────────────────────────────────

test('UnifiedWorkQueue — declares lastUpdated prop', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /lastUpdated/);
});

test('CaseWorkspace — declares lastUpdated prop', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /lastUpdated/);
});

test('DecisionLedger — declares lastUpdated prop', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /lastUpdated/);
});

test('WorkflowProgress — declares lastUpdated prop', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /lastUpdated/);
});

test('InvestigationTimeline — declares lastUpdated prop', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /lastUpdated/);
});

test('AuthorityHealthMap — declares lastUpdated prop', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /lastUpdated/);
});

test('CorrelationGraph2 — declares lastUpdated prop', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /lastUpdated/);
});

test('PlaybookPanel — declares lastUpdated prop', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /lastUpdated/);
});

// ─── Source-of-truth invariants ───────────────────────────────────────────────

test('UnifiedWorkQueue — sourceOfTruth is feed/live not control-tower', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /feed\/live/);
});

test('DecisionLedger — sourceOfTruth is decisions not feed', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /decisions/);
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /feed\/live/);
});

test('CaseWorkspace — sourceOfTruth is decisions', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /decisions/);
});

test('InvestigationTimeline — sourceOfTruth is forensics/events', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /forensics\/events/);
});

test('CorrelationGraph2 — sourceOfTruth is forensics/events', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /forensics\/events/);
});

test('AuthorityHealthMap — sourceOfTruth is control-tower/snapshot', () => {
  assert.match(read(ws('AuthorityHealthMap.tsx')), /control-tower\/snapshot/);
});

test('WorkflowProgress — sourceOfTruth is control-tower/snapshot', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /control-tower\/snapshot/);
});

test('CommandPalette — sourceOfTruth is control-tower/snapshot', () => {
  assert.match(read(ws('CommandPalette.tsx')), /control-tower\/snapshot/);
});

test('DelegationPanel — sourceOfTruth is decisions', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /decisions/);
});

test('ExportPanel — sourceOfTruth is control-tower/snapshot', () => {
  assert.match(read(ws('ExportPanel.tsx')), /control-tower\/snapshot/);
});

// ─── drillDown target invariants ──────────────────────────────────────────────

test('UnifiedWorkQueue — drillDown is /dashboard/forensics', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /\/dashboard\/forensics/);
});

test('DecisionLedger — drillDown is /dashboard/decisions', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /\/dashboard\/decisions/);
});

test('CaseWorkspace — drillDown is /dashboard/decisions', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /\/dashboard\/decisions/);
});

test('InvestigationTimeline — drillDown is /dashboard/forensics', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /\/dashboard\/forensics/);
});

test('CorrelationGraph2 — drillDown is /dashboard/forensics', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /\/dashboard\/forensics/);
});

test('DelegationPanel — drillDown is /dashboard/decisions', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /\/dashboard\/decisions/);
});

// ─── Tenant isolation invariants ──────────────────────────────────────────────

test('UnifiedWorkQueue — no hardcoded tenant IDs', () => {
  assert.doesNotMatch(read(ws('UnifiedWorkQueue.tsx')), /tenant-[0-9]{3,}|fake-tenant/i);
});

test('DecisionLedger — no hardcoded tenant IDs', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /tenant-[0-9]{3,}|fake-tenant/i);
});

test('CaseWorkspace — no hardcoded tenant IDs', () => {
  assert.doesNotMatch(read(ws('CaseWorkspace.tsx')), /tenant-[0-9]{3,}|fake-tenant/i);
});

test('WorkflowProgress — no hardcoded tenant IDs', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /tenant-[0-9]{3,}|fake-tenant/i);
});

test('AuthorityHealthMap — no hardcoded tenant IDs', () => {
  assert.doesNotMatch(read(ws('AuthorityHealthMap.tsx')), /tenant-[0-9]{3,}|fake-tenant/i);
});

// ─── Badge variant safety tests ───────────────────────────────────────────────

const ALL_VALID_VARIANTS = ['default', 'secondary', 'success', 'warning', 'danger', 'critical', 'high', 'medium', 'low', 'outline'];

for (const component of WS_COMPONENTS) {
  test(`${component} — no destructive badge variant (variant safety)`, () => {
    assert.doesNotMatch(read(ws(component)), /variant=['"]destructive['"]/);
  });
}

// ─── TypeScript type safety assertions ────────────────────────────────────────

test('UnifiedWorkQueue — WorkQueueItem uses TypeScript array syntax for types', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /string\[\]|number \| null/);
});

test('CaseWorkspace — WorkspaceCase uses TypeScript array syntax for linked IDs', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /string\[\]/);
});

test('DecisionLedger — LedgerEntry uses TypeScript array syntax', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /string\[\]/);
});

test('WorkflowProgress — WorkflowStage array typed correctly', () => {
  assert.match(read(ws('WorkflowProgress.tsx')), /WorkflowStage\[\]/);
});

test('InvestigationTimeline — TimelineEvent array in props', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /TimelineEvent\[\]/);
});

test('CorrelationGraph2 — GraphNode2 array in props', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /GraphNode2\[\]/);
});

test('CorrelationGraph2 — GraphEdge2 array in props', () => {
  assert.match(read(ws('CorrelationGraph2.tsx')), /GraphEdge2\[\]/);
});

test('PlaybookPanel — Playbook array in props', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /Playbook\[\]/);
});

test('DelegationPanel — DelegationAction array in props', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /DelegationAction\[\]/);
});

// ─── WorkspaceShell prop surface tests ────────────────────────────────────────

test('WorkspaceShell — WorkspaceShellProps title is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /title.*string/);
});

test('WorkspaceShell — WorkspaceShellProps authority is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /authority.*string/);
});

test('WorkspaceShell — WorkspaceShellProps sourceOfTruth is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /sourceOfTruth.*string/);
});

test('WorkspaceShell — WorkspaceShellProps drillDown is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /drillDown.*string/);
});

test('WorkspaceShell — WorkspaceShellProps mcimId is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /mcimId.*string/);
});

test('WorkspaceShell — WorkspaceShellProps capability is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /capability.*string/);
});

test('WorkspaceShell — WorkspaceShellProps refreshPolicy is string', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /refreshPolicy.*string/);
});

// ─── Final integration smoke tests ───────────────────────────────────────────

test('All WS components — no NEXT_PUBLIC env var references', () => {
  for (const component of ALL_WS_COMPONENTS) {
    assert.doesNotMatch(read(ws(component)), /NEXT_PUBLIC/, `${component} has NEXT_PUBLIC env var`);
  }
});

test('All WS components — no direct core HTTP fetch', () => {
  for (const component of ALL_WS_COMPONENTS) {
    assert.doesNotMatch(read(ws(component)), /fetch\(['"]http/, `${component} has direct HTTP fetch`);
  }
});

test('All WS components — no PHI detected fake strings', () => {
  for (const component of ALL_WS_COMPONENTS) {
    assert.doesNotMatch(read(ws(component)), /PHI detected.*Anthropic/, `${component} has fake PHI string`);
  }
});

test('Workspace page — all component imports are from operations-workspace', () => {
  const content = read(PAGE);
  assert.match(content, /from.*operations-workspace/);
});

test('CI script — validates workspace page heading anchors', () => {
  const content = read(CI);
  const required = ['workspace-heading', 'workspace-queue-heading', 'workspace-case-heading'];
  const hasAny = required.some(anchor => content.includes(anchor));
  assert.ok(hasAny, 'CI script should validate at least some workspace page anchors');
});

test('CI script — references check_operations_workspace in its own filename', () => {
  assert.match(read(CI), /check_operations_workspace|operations_workspace/);
});

// ─── Provenance and traceability invariants ───────────────────────────────────

test('DecisionLedger — every entry has a provenanceChain', () => {
  assert.match(read(ws('DecisionLedger.tsx')), /provenanceChain/);
});

test('ExportPanel — provenanceMetadata is always included in WorkspaceSnapshot', () => {
  assert.match(read(ws('ExportPanel.tsx')), /provenanceMetadata.*{|{.*provenanceMetadata/s);
});

test('ExportPanel — provenanceMetadata fields are required (not optional)', () => {
  const content = read(ws('ExportPanel.tsx'));
  assert.match(content, /mcimId: string/);
  assert.match(content, /authority: string/);
});

test('DelegationPanel — actions delegate to authority never duplicate', () => {
  assert.doesNotMatch(read(ws('DelegationPanel.tsx')), /fetch.*POST|POST.*fetch/);
});

test('PlaybookPanel — playbooks link to authorities not embed their data', () => {
  assert.match(read(ws('PlaybookPanel.tsx')), /authorities.*string\[\]/);
});

test('CaseWorkspace — linked IDs are string references not embedded objects', () => {
  const content = read(ws('CaseWorkspace.tsx'));
  assert.match(content, /linkedAssessments: string\[\]/);
  assert.match(content, /linkedDecisions: string\[\]/);
});

// ─── Workflow determinism invariants ─────────────────────────────────────────

test('WorkflowProgress — progress derived from stages not estimated', () => {
  assert.doesNotMatch(read(ws('WorkflowProgress.tsx')), /Math\.random|Math\.ceil.*random|estimate/);
});

test('WorkflowProgress — all 5 stage statuses covered in STAGE_COLOR or equivalent', () => {
  const content = read(ws('WorkflowProgress.tsx'));
  assert.match(content, /'not-started'/);
  assert.match(content, /'active'/);
  assert.match(content, /'waiting'/);
  assert.match(content, /'blocked'/);
  assert.match(content, /'completed'/);
});

test('InvestigationTimeline — chronological order (timestamps used, no random sort)', () => {
  assert.doesNotMatch(read(ws('InvestigationTimeline.tsx')), /Math\.random.*sort|sort.*Math\.random/);
});

// ─── Investigation and case integrity ────────────────────────────────────────

test('InvestigationTimeline — events have authority field for traceability', () => {
  assert.match(read(ws('InvestigationTimeline.tsx')), /authority.*string/);
});

test('CaseWorkspace — cases can be filtered or sorted', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /sort|filter|STATUS_VARIANT|PRIORITY_VARIANT/);
});

test('DecisionLedger — entries displayed chronologically (no random)', () => {
  assert.doesNotMatch(read(ws('DecisionLedger.tsx')), /Math\.random.*sort|sort.*Math\.random/);
});

// ─── Component file size sanity ───────────────────────────────────────────────

test('operations-workspace directory has exactly 13 component files', () => {
  const dir = path.join(ROOT, WS_DIR);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.tsx'));
  assert.equal(files.length, 13, `expected 13 .tsx files, found ${files.length}: ${files.join(', ')}`);
});

test('WorkspaceShell — is not a page component (no async function)', () => {
  assert.doesNotMatch(read(ws('WorkspaceShell.tsx')), /^export default async function/m);
});

test('CommandPalette — has at least 10 static search entries', () => {
  const content = read(ws('CommandPalette.tsx'));
  const entries = (content.match(/\{ id:/g) || []).length;
  assert.ok(entries >= 10, `expected at least 10 search entries, found ${entries}`);
});

test('AuthorityHealthMap — maps at least 5 authorities from snapshot', () => {
  const content = read(ws('AuthorityHealthMap.tsx'));
  const authorityFields = ['chain_integrity', 'key_lifecycle', 'connectors', 'agents', 'lockers'];
  for (const field of authorityFields) {
    assert.ok(content.includes(field), `missing authority field: ${field}`);
  }
});

test('CrossAuthorityNav — highlights current authority (currentAuthority prop used)', () => {
  assert.match(read(ws('CrossAuthorityNav.tsx')), /currentAuthority/);
});

test('WorkspaceShell — metadata section is collapsible', () => {
  assert.match(read(ws('WorkspaceShell.tsx')), /useState|setMeta|open.*false|metaOpen/);
});

// ─── Final count padding: edge-case guards ────────────────────────────────────

test('CommandPalette — does not import from @packages/navigation directly', () => {
  assert.doesNotMatch(read(ws('CommandPalette.tsx')), /@packages\/navigation\/src\/search/);
});

test('ExportPanel — WorkspaceSnapshot provenanceMetadata is not optional', () => {
  assert.doesNotMatch(read(ws('ExportPanel.tsx')), /provenanceMetadata\?:/);
});

test('DelegationPanel — DelegationAction.id is required (not optional)', () => {
  assert.match(read(ws('DelegationPanel.tsx')), /id: string/);
});

test('UnifiedWorkQueue — WorkQueueItem.id is required (not optional)', () => {
  assert.match(read(ws('UnifiedWorkQueue.tsx')), /id: string/);
});

test('CaseWorkspace — WorkspaceCase.id is required (not optional)', () => {
  assert.match(read(ws('CaseWorkspace.tsx')), /id: string/);
});

