'use strict';

const LEGACY_INTERNAL_ROLE = 'legacy_console_user';

const PORTAL_ONLY_ROLE_MARKERS = ['portal_only', 'Customer', 'MSP'];
const CLIENT_CONSOLE_ROLES = [
  'tenant_admin',
  'client_executive',
  'client_compliance',
  'client_auditor',
  'client_remediation_owner',
  'client_security_owner',
  'client_read_only',
];
const CLIENT_MUTATION_ROLES = ['tenant_admin'];
const INTERNAL_CONSOLE_ROLES = [
  'Operator',
  'Administrator',
  'CISO',
  'Executive',
  'Auditor',
  'Developer',
  'Support',
  'Compliance',
  'AssessmentEngineer',
  'FieldAssessor',
  'Consultant',
  LEGACY_INTERNAL_ROLE,
];
const RECOGNIZED_ROLES = new Set([
  ...PORTAL_ONLY_ROLE_MARKERS,
  ...CLIENT_CONSOLE_ROLES,
  ...INTERNAL_CONSOLE_ROLES,
]);

const ROLE_CLAIM_KEYS = [
  'roles',
  'role',
  'https://frostgate.ai/roles',
  'https://frostgate.app/roles',
  'https://frostgate.dev/roles',
];
const TENANT_CLAIM_KEYS = [
  'tenant_id',
  'tenantId',
  'https://frostgate.ai/tenant_id',
  'https://frostgate.app/tenant_id',
  'https://frostgate.dev/tenant_id',
];

const CLIENT_CONSOLE_ALLOWED_ROLES = [...CLIENT_CONSOLE_ROLES, ...INTERNAL_CONSOLE_ROLES];
const INTERNAL_ONLY_ROLES = [...INTERNAL_CONSOLE_ROLES];
const SUPPORT_LIMITED_ROLES = ['Support', 'Administrator', LEGACY_INTERNAL_ROLE];
const TENANT_ADMIN_CONSOLE_ROLES = ['tenant_admin', 'client_remediation_owner', ...INTERNAL_CONSOLE_ROLES];

function routeAudit({
  id,
  title,
  routePattern,
  audience,
  allowedRoles,
  backendApis = [],
  navVisible = true,
  directlyRoutable = true,
  tenantScoped = false,
  clientSafe = false,
  exposesInternalMetadata = false,
  readOnly = true,
  allowsMutation = false,
  exportsSanitized = false,
  notes = '',
}) {
  return {
    id,
    title,
    routePattern,
    audience,
    navVisible,
    directlyRoutable,
    allowedRoles,
    backendApis,
    tenantScoped,
    clientSafe,
    exposesInternalMetadata,
    readOnly,
    allowsMutation,
    exportsSanitized,
    notes,
  };
}

const CONSOLE_ROUTE_AUDITS = [
  routeAudit({
    id: 'console-landing',
    title: 'Landing',
    routePattern: '/',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'console-login',
    title: 'Login',
    routePattern: '/login',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'command-center',
    title: 'Command Center',
    routePattern: '/dashboard',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [
      '/api/core/control-tower/snapshot',
      '/api/core/health/ready',
      '/api/core/feed/live',
      '/api/core/decisions',
      '/api/core/control-plane/readiness/frameworks',
      '/api/core/control-plane/readiness/assessments',
      '/api/core/field-assessment/engagements',
    ],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
    exportsSanitized: false,
  }),
  routeAudit({
    id: 'operations-center',
    title: 'Operations Center',
    routePattern: '/dashboard/operations-center',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'control-tower',
    title: 'Control Tower',
    routePattern: '/dashboard/control-tower',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/control-tower/snapshot'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
  }),
  routeAudit({
    id: 'executive-intelligence',
    title: 'Executive Intelligence',
    routePattern: '/dashboard/executive',
    audience: 'client_console_limited',
    allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES,
    backendApis: ['/api/core/api/executive/*'],
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'readiness',
    title: 'Readiness',
    routePattern: '/dashboard/readiness',
    audience: 'client_console_limited',
    allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES,
    backendApis: [
      '/api/core/control-plane/readiness/frameworks',
      '/api/core/control-plane/readiness/assessments',
      '/api/core/control-plane/readiness/domains',
      '/api/core/control-plane/readiness/controls',
      '/api/core/control-plane/readiness/maturity-tiers',
    ],
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'field-assessments',
    title: 'Field Assessments',
    routePattern: '/field-assessment',
    audience: 'tenant_admin_console',
    allowedRoles: TENANT_ADMIN_CONSOLE_ROLES,
    backendApis: ['/api/core/field-assessment/engagements'],
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: false,
    allowsMutation: true,
    exportsSanitized: true,
    notes: 'Client access is limited to tenant-scoped engagement data. Mutations remain role-gated.',
  }),
  routeAudit({
    id: 'field-assessment-detail',
    title: 'Field Assessment Detail',
    routePattern: '/field-assessment/[engagementId]',
    audience: 'tenant_admin_console',
    allowedRoles: TENANT_ADMIN_CONSOLE_ROLES,
    backendApis: ['/api/core/field-assessment/engagements/*'],
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: false,
    allowsMutation: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'policies',
    title: 'Policies',
    routePattern: '/dashboard/policies',
    audience: 'unknown_needs_review',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
    notes: 'Prompt requires a limited client-safe policy view, but this route is still an internal authoring surface.',
  }),
  routeAudit({
    id: 'providers',
    title: 'Providers',
    routePattern: '/dashboard/providers',
    audience: 'forbidden_to_clients',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [
      '/api/core/ui/provider/governance',
      '/api/core/ui/provider/routing',
      '/api/core/ui/provider/failover',
    ],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'governance-topology',
    title: 'Governance Topology',
    routePattern: '/governance/topology',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/governance/graph', '/api/core/governance/assets'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'ai-workspace',
    title: 'AI Workspace',
    routePattern: '/dashboard/assistant',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/ui/ai/chat'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'corpus',
    title: 'Corpus',
    routePattern: '/dashboard/corpus',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/rag/corpora', '/api/core/rag/documents'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'retrieval',
    title: 'Retrieval',
    routePattern: '/dashboard/retrieval',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/rag/retrieval-policy', '/api/core/rag/corpora'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'workforce-intel',
    title: 'Workforce Intel',
    routePattern: '/dashboard/workforce',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/workforce/users', '/api/core/portal/grants'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'ingestion',
    title: 'Ingestion',
    routePattern: '/dashboard/ingestion',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/rag/upload', '/api/core/rag/uploads'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'provenance',
    title: 'Provenance',
    routePattern: '/dashboard/provenance',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/ui/forensics/events', '/api/core/ui/forensics/trace'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
  }),
  routeAudit({
    id: 'decisions',
    title: 'Decisions',
    routePattern: '/dashboard/decisions',
    audience: 'client_console_limited',
    allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES,
    backendApis: ['/api/core/decisions'],
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'forensics',
    title: 'Audit & Forensics',
    routePattern: '/dashboard/forensics',
    audience: 'unknown_needs_review',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [
      '/api/core/forensics/snapshot',
      '/api/core/forensics/audit_trail',
      '/api/core/forensics/chain/verify',
    ],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
    exportsSanitized: false,
    notes: 'Client-safe audit view requested in prompt is not implemented on this route yet.',
  }),
  routeAudit({
    id: 'alignment',
    title: 'Alignment',
    routePattern: '/dashboard/alignment',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/alignment-artifact'],
    tenantScoped: false,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
  }),
  routeAudit({
    id: 'audit-specialist',
    title: 'Audit',
    routePattern: '/audit',
    audience: 'unknown_needs_review',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
    exportsSanitized: false,
    notes: 'The current page accepts free-form tenant IDs and needs a sanitized client-safe mode before client access.',
  }),
  routeAudit({
    id: 'evaluation-lab',
    title: 'Evaluation Lab',
    routePattern: '/dashboard/evaluation',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/ui/evaluation/runs', '/api/core/ui/evaluation/quality'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'clients',
    title: 'Clients',
    routePattern: '/admin/tenants',
    audience: 'support_limited',
    allowedRoles: SUPPORT_LIMITED_ROLES,
    backendApis: ['/api/tenants', '/api/admin/provision-tenant'],
    tenantScoped: false,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'client-detail',
    title: 'Client Detail',
    routePattern: '/admin/tenants/[tenantId]',
    audience: 'support_limited',
    allowedRoles: SUPPORT_LIMITED_ROLES,
    backendApis: ['/api/email', '/api/core/admin/identity/*'],
    tenantScoped: false,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'keys',
    title: 'Keys',
    routePattern: '/keys',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/keys'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'settings',
    title: 'Settings',
    routePattern: '/dashboard/settings',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [],
    tenantScoped: false,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'workspace-integration',
    title: 'Workspace Integration',
    routePattern: '/workspace-integration',
    audience: 'platform_internal',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: [],
    directlyRoutable: false,
    navVisible: false,
    tenantScoped: false,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
    notes: 'Navigation registry entry exists but no app route is present in the console app.',
  }),
  routeAudit({
    id: 'operations-workspace',
    title: 'Operations Workspace',
    routePattern: '/workspace',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/control-tower/snapshot'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
  }),
  routeAudit({
    id: 'trust-center-workspace',
    title: 'Trust Center',
    routePattern: '/trust-center',
    audience: 'unknown_needs_review',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/control-tower/snapshot'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: true,
    exportsSanitized: false,
    notes: 'Prompt expects a limited client-safe trust center, but the current route still depends on operator snapshot data.',
  }),
  routeAudit({
    id: 'onboarding',
    title: 'Onboarding',
    routePattern: '/onboarding',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'products',
    title: 'Products',
    routePattern: '/products',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'product-detail',
    title: 'Product Detail',
    routePattern: '/products/[productId]',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'product-new',
    title: 'New Product',
    routePattern: '/products/new',
    audience: 'client_portal',
    allowedRoles: [],
    backendApis: [],
    tenantScoped: false,
    clientSafe: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'assessment-legacy',
    title: 'Assessments',
    routePattern: '/assessment',
    audience: 'frostgate_operator',
    allowedRoles: INTERNAL_ONLY_ROLES,
    backendApis: ['/api/core/ingest/assessment/*'],
    tenantScoped: true,
    clientSafe: false,
    exposesInternalMetadata: true,
    readOnly: false,
    allowsMutation: true,
  }),
  routeAudit({
    id: 'reports',
    title: 'Reports',
    routePattern: '/reports',
    audience: 'client_console_limited',
    allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES,
    backendApis: [],
    navVisible: false,
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: true,
    exportsSanitized: true,
  }),
  routeAudit({
    id: 'report-viewer',
    title: 'Report Viewer',
    routePattern: '/reports/[reportId]',
    audience: 'client_console_limited',
    allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES,
    backendApis: [
      '/api/core/ingest/assessment/reports/*',
      '/api/core/ingest/assessment/reports/*/download',
    ],
    navVisible: false,
    tenantScoped: true,
    clientSafe: true,
    exposesInternalMetadata: false,
    readOnly: true,
    exportsSanitized: true,
  }),
];

const CORE_API_POLICIES = [
  { prefix: 'health/live', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: true },
  { prefix: 'health/ready', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: true },
  { prefix: 'stats/summary', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: true },
  { prefix: 'feed/live', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'decisions', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'forensics/chain/verify', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'forensics/snapshot', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'forensics/audit_trail', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'keys', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'control-tower/snapshot', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'admin/connectors/status', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: true },
  { prefix: 'admin/connectors', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'admin/agent/devices', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: true },
  { prefix: 'admin/agent/quarantine', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'admin/agent/unquarantine', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'control-plane/lockers', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'audit/export', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ingest/assessment', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'ui/ai/chat', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'rag/retrieval-policy', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'rag/corpora', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'rag/documents', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'rag/upload', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'rag/uploads', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/forensics/events', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/forensics/trace', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/provider/governance', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/provider/routing', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/provider/failover', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/evaluation/runs', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'ui/evaluation/quality', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'control-plane/readiness/frameworks', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'control-plane/readiness/assessments', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'control-plane/readiness/domains', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'control-plane/readiness/controls', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'control-plane/readiness/maturity-tiers', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'ui/audit/overview', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'ui/audit/status', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'ui/audit/chain-integrity', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
  { prefix: 'field-assessment/engagements', allowedRoles: TENANT_ADMIN_CONSOLE_ROLES, tenantScoped: true, clientSafe: true, readOnly: false, mutationRoles: ['tenant_admin', ...INTERNAL_ONLY_ROLES] },
  { prefix: 'governance/graph', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'governance/assets', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: true, clientSafe: false, readOnly: true },
  { prefix: 'workforce/users', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'portal/grants', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'admin/identity/tenants', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'admin/identity/invitations', allowedRoles: INTERNAL_ONLY_ROLES, tenantScoped: false, clientSafe: false, readOnly: false, mutationRoles: INTERNAL_ONLY_ROLES },
  { prefix: 'api/executive', allowedRoles: CLIENT_CONSOLE_ALLOWED_ROLES, tenantScoped: true, clientSafe: true, readOnly: true },
];

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function dedupe(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function normalizePathname(pathname) {
  if (!pathname) return '/';
  const stripped = pathname.split('?')[0].split('#')[0] || '/';
  if (stripped !== '/' && stripped.endsWith('/')) {
    return stripped.slice(0, -1);
  }
  return stripped || '/';
}

function toRoleList(value) {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => toRoleList(entry));
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
}

function configuredClaimKey(envName, fallback) {
  const raw = (typeof process !== 'undefined' && process.env && process.env[envName]) || '';
  const value = raw.trim();
  return value ? [value, ...fallback] : fallback;
}

function readClaimValues(source, keys) {
  if (!isRecord(source)) return [];
  const values = [];
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      values.push(...toRoleList(source[key]));
    }
  }
  return values;
}

function readTenantValue(source, keys) {
  if (!isRecord(source)) return null;
  for (const key of keys) {
    const value = source[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function extractClaimSources(source) {
  const sources = [source];
  if (isRecord(source)) {
    if (isRecord(source.user)) sources.push(source.user);
    if (isRecord(source.token)) sources.push(source.token);
    if (isRecord(source.profile)) sources.push(source.profile);
    if (isRecord(source.app_metadata)) sources.push(source.app_metadata);
    if (isRecord(source.user_metadata)) sources.push(source.user_metadata);
    if (isRecord(source.user) && isRecord(source.user.app_metadata)) sources.push(source.user.app_metadata);
    if (isRecord(source.user) && isRecord(source.user.user_metadata)) sources.push(source.user.user_metadata);
  }
  return sources;
}

function resolveRecognizedRoles(source) {
  const roleKeys = configuredClaimKey('AUTH0_ROLES_CLAIM', ROLE_CLAIM_KEYS);
  const roles = dedupe(
    extractClaimSources(source)
      .flatMap((entry) => readClaimValues(entry, roleKeys))
      .map((entry) => String(entry).trim())
      .filter(Boolean),
  );

  const recognized = roles.filter((role) => RECOGNIZED_ROLES.has(role));
  const unrecognized = roles.filter((role) => !RECOGNIZED_ROLES.has(role));

  return {
    explicitRoles: roles,
    recognizedRoles: dedupe(recognized),
    unrecognizedRoles: dedupe(unrecognized),
  };
}

function resolveTenantId(source) {
  const tenantKeys = configuredClaimKey('AUTH0_TENANT_ID_CLAIM', TENANT_CLAIM_KEYS);
  for (const entry of extractClaimSources(source)) {
    const tenantId = readTenantValue(entry, tenantKeys);
    if (tenantId) return tenantId;
  }
  return null;
}

function resolveConsolePrincipal(source) {
  if (!source) {
    return {
      experienceClass: 'anonymous',
      isAuthenticated: false,
      roles: [],
      explicitRoles: [],
      tenantId: null,
    };
  }

  const { explicitRoles, recognizedRoles, unrecognizedRoles } = resolveRecognizedRoles(source);
  const tenantId = resolveTenantId(source);

  if (recognizedRoles.length === 0) {
    const allowLegacy = ((typeof process !== 'undefined' && process.env && process.env.FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK) || 'true') !== 'false';
    if (!allowLegacy || explicitRoles.length > 0 || unrecognizedRoles.length > 0) {
      return {
        experienceClass: 'unsupported',
        isAuthenticated: true,
        roles: recognizedRoles,
        explicitRoles,
        unrecognizedRoles,
        tenantId,
      };
    }

    return {
      experienceClass: 'legacy_internal',
      isAuthenticated: true,
      roles: [LEGACY_INTERNAL_ROLE],
      explicitRoles: [],
      tenantId,
    };
  }

  const hasPortalOnlyRole = recognizedRoles.some((role) => PORTAL_ONLY_ROLE_MARKERS.includes(role));
  const hasClientConsoleRole = recognizedRoles.some((role) => CLIENT_CONSOLE_ROLES.includes(role));
  const hasInternalRole = recognizedRoles.some((role) => INTERNAL_CONSOLE_ROLES.includes(role));

  if (hasPortalOnlyRole && !hasClientConsoleRole && !hasInternalRole) {
    return {
      experienceClass: 'portal_only',
      isAuthenticated: true,
      roles: recognizedRoles,
      explicitRoles,
      tenantId,
    };
  }

  if (hasClientConsoleRole && !hasInternalRole) {
    return {
      experienceClass: 'console_enabled_client',
      isAuthenticated: true,
      roles: recognizedRoles,
      explicitRoles,
      tenantId,
    };
  }

  if (hasInternalRole) {
    return {
      experienceClass: 'internal_console',
      isAuthenticated: true,
      roles: recognizedRoles,
      explicitRoles,
      tenantId,
    };
  }

  return {
    experienceClass: 'unsupported',
    isAuthenticated: true,
    roles: recognizedRoles,
    explicitRoles,
    unrecognizedRoles,
    tenantId,
  };
}

function matchRoutePattern(pattern, pathname) {
  const normalizedPattern = normalizePathname(pattern);
  const normalizedPath = normalizePathname(pathname);

  const patternParts = normalizedPattern.split('/').filter(Boolean);
  const pathParts = normalizedPath.split('/').filter(Boolean);

  if (patternParts.length !== pathParts.length) return false;

  for (let i = 0; i < patternParts.length; i += 1) {
    const expected = patternParts[i];
    const actual = pathParts[i];
    if (expected.startsWith('[') && expected.endsWith(']')) continue;
    if (expected !== actual) return false;
  }

  return true;
}

function getConsoleRouteAudit(pathname) {
  const normalized = normalizePathname(pathname);
  return (
    CONSOLE_ROUTE_AUDITS.find((entry) => matchRoutePattern(entry.routePattern, normalized)) ||
    null
  );
}

function hasAllowedRole(principal, allowedRoles) {
  if (!allowedRoles || allowedRoles.length === 0) return true;
  return principal.roles.some((role) => allowedRoles.includes(role));
}

function canAccessConsoleRoute(pathname, source) {
  const audit = getConsoleRouteAudit(pathname);
  if (!audit) return false;
  if (audit.audience === 'client_portal') return true;

  const principal = resolveConsolePrincipal(source);
  if (!principal.isAuthenticated) return false;
  if (principal.experienceClass === 'portal_only') return false;
  if (principal.experienceClass === 'unsupported') return false;

  return hasAllowedRole(principal, audit.allowedRoles);
}

function getCoreApiPolicy(pathOrSegments) {
  const joined = Array.isArray(pathOrSegments)
    ? pathOrSegments.join('/')
    : String(pathOrSegments || '').replace(/^\/+/, '');

  return (
    CORE_API_POLICIES.find((entry) => joined === entry.prefix || joined.startsWith(`${entry.prefix}/`)) ||
    null
  );
}

function canAccessCoreApiPath(pathOrSegments, method, source) {
  const policy = getCoreApiPolicy(pathOrSegments);
  if (!policy) return false;

  const principal = resolveConsolePrincipal(source);
  if (!principal.isAuthenticated) return false;
  if (principal.experienceClass === 'portal_only') return false;
  if (principal.experienceClass === 'unsupported') return false;
  if (!hasAllowedRole(principal, policy.allowedRoles)) return false;

  const upperMethod = String(method || 'GET').toUpperCase();
  if (upperMethod === 'GET' || upperMethod === 'HEAD') return true;

  const mutationRoles = policy.mutationRoles || INTERNAL_ONLY_ROLES;
  return hasAllowedRole(principal, mutationRoles);
}

function getNavigationItemsForPrincipal(items, source) {
  return items.filter(
    (item) => item.visibility === 'visible' && canAccessConsoleRoute(item.route, source),
  );
}

function getSessionClaims(source) {
  const principal = resolveConsolePrincipal(source);
  return {
    roles: principal.roles,
    tenantId: principal.tenantId,
    experienceClass: principal.experienceClass,
  };
}

module.exports = {
  CLIENT_CONSOLE_ROLES,
  CLIENT_MUTATION_ROLES,
  CONSOLE_ROUTE_AUDITS,
  CORE_API_POLICIES,
  INTERNAL_CONSOLE_ROLES,
  LEGACY_INTERNAL_ROLE,
  canAccessConsoleRoute,
  canAccessCoreApiPath,
  getConsoleRouteAudit,
  getCoreApiPolicy,
  getNavigationItemsForPrincipal,
  getSessionClaims,
  matchRoutePattern,
  normalizePathname,
  resolveConsolePrincipal,
};
