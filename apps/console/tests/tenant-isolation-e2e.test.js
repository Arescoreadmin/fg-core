'use strict';

/**
 * TENANT-ISOLATION-E2E-001 — production authority decision contract.
 *
 * The behavioral cases call the same resolveTenantRequestAuthority function
 * used by the Console BFF. Source assertions then pin the route wiring, Core
 * delegation/membership chain, and persistence boundaries that cannot run in
 * a standalone Node process.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  CORE_API_POLICIES,
  canAccessConsoleRoute,
  canAccessCoreApiPath,
  isPlatformAdminSession,
  resolveConsolePrincipal,
  resolveTenantRequestAuthority,
} = require('../lib/consoleAccess');

const TENANT_A = 'high-table-financial';
const TENANT_B = 'continental-holdings';
const OPERATOR_TENANT = 'frostgate';
const ALPHA = 'ALPHA_ONLY_706';
const BRAVO = 'BRAVO_ONLY_706';
const OPERATOR = 'OPERATOR_ONLY_706';

function read(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

function readRepo(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', '..', '..', relativePath), 'utf8');
}

function session(roles, tenantId, id = 'auth0|actor') {
  const user = { roles, id };
  if (tenantId !== undefined) user.tenant_id = tenantId;
  return { user };
}

const tenantAAdmin = session(['tenant_admin'], TENANT_A, 'auth0|high-table-admin');
const tenantBAdmin = session(['tenant_admin'], TENANT_B, 'auth0|continental-admin');
const administrator = session(['Administrator'], OPERATOR_TENANT, 'auth0|platform-admin');
const support = session(['Support'], OPERATOR_TENANT, 'auth0|support');

function resolve(source, queryTenantIds = [], pathTenantId = null, allowOperatorFallback = true) {
  return resolveTenantRequestAuthority(source, {
    queryTenantIds,
    pathTenantId,
    allowOperatorFallback,
  });
}

function assertDenied(result, status, code) {
  assert.equal(result.ok, false);
  assert.equal(result.status, status);
  assert.equal(result.code, code);
}

// P-62a / requested-context matrix — exercises the real production resolver.
test('A own tenant query resolves to Tenant A', () => {
  assert.deepEqual(resolve(tenantAAdmin, [TENANT_A]), {
    ok: true, tenantId: TENANT_A, authority: 'tenant_human', source: 'requested',
  });
});

test('B foreign tenant query is denied', () => {
  assertDenied(resolve(tenantAAdmin, [TENANT_B]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('C nonexistent tenant query is indistinguishable from foreign tenant', () => {
  const foreign = resolve(tenantAAdmin, [TENANT_B]);
  const nonexistent = resolve(tenantAAdmin, ['tenant-does-not-exist-706']);
  assert.deepEqual(nonexistent, foreign);
});

test('D missing tenant derives canonical client session tenant', () => {
  const result = resolve(tenantAAdmin);
  assert.equal(result.ok, true);
  assert.equal(result.tenantId, TENANT_A);
  assert.equal(result.source, 'session');
  assert.notEqual(result.tenantId, OPERATOR_TENANT);
});

for (const [name, value] of [
  ['E empty', ''],
  ['F whitespace', '   '],
  ['G slash malformed', '../continental'],
  ['H dot malformed', 'continental.example'],
  ['I overlong', 'a'.repeat(129)],
]) {
  test(`${name} tenant context fails closed`, () => {
    assertDenied(resolve(tenantAAdmin, [value]), 422, 'TENANT_CONTEXT_INVALID');
  });
}

test('J equal duplicate tenant query is rejected as ambiguous', () => {
  assertDenied(resolve(tenantAAdmin, [TENANT_A, TENANT_A]), 422, 'TENANT_CONTEXT_AMBIGUOUS');
});

test('K conflicting duplicate tenant query is rejected as ambiguous', () => {
  assertDenied(resolve(tenantAAdmin, [TENANT_A, TENANT_B]), 422, 'TENANT_CONTEXT_AMBIGUOUS');
});

test('L own path tenant resolves', () => {
  const result = resolve(tenantAAdmin, [], TENANT_A);
  assert.equal(result.ok, true);
  assert.equal(result.tenantId, TENANT_A);
});

test('M foreign path tenant is denied', () => {
  assertDenied(resolve(tenantAAdmin, [], TENANT_B), 403, 'TENANT_AUTHORITY_DENIED');
});

test('N own path plus foreign query is denied before authority use', () => {
  assertDenied(resolve(tenantAAdmin, [TENANT_B], TENANT_A), 403, 'TENANT_CONTEXT_MISMATCH');
});

test('O foreign path plus own query is denied before authority use', () => {
  assertDenied(resolve(tenantAAdmin, [TENANT_A], TENANT_B), 403, 'TENANT_CONTEXT_MISMATCH');
});

test('P matching path and query remains Tenant A only', () => {
  const result = resolve(tenantAAdmin, [TENANT_A], TENANT_A);
  assert.equal(result.ok, true);
  assert.equal(result.tenantId, TENANT_A);
});

test('Q missing canonical session tenant fails closed', () => {
  assertDenied(resolve(session(['tenant_admin'])), 403, 'TENANT_AUTHORITY_MISSING');
});

test('R malformed canonical session tenant fails closed', () => {
  assertDenied(resolve(session(['tenant_admin'], '../../operator')), 403, 'TENANT_AUTHORITY_MISSING');
});

test('S configured operator fallback is impossible for client human authority', () => {
  for (const requested of [[], [TENANT_A]]) {
    const result = resolve(tenantAAdmin, requested);
    assert.equal(result.ok, true);
    assert.equal(Boolean(result.operatorFallback), false);
  }
});

test('T internal operator missing context explicitly selects configured fallback mode', () => {
  const result = resolve(administrator);
  assert.equal(result.ok, true);
  assert.equal(result.operatorFallback, true);
  assert.equal(result.source, 'configured_operator');
  assert.equal(result.tenantId, null);
});

test('U internal operator explicit cross-tenant selection remains functional', () => {
  for (const tenantId of [TENANT_A, TENANT_B]) {
    const result = resolve(administrator, [tenantId]);
    assert.equal(result.ok, true);
    assert.equal(result.tenantId, tenantId);
    assert.equal(result.source, 'requested');
  }
});

test('V internal request without explicit fallback permission fails closed', () => {
  assertDenied(resolve(administrator, [], null, false), 422, 'TENANT_CONTEXT_MISSING');
});

// Authority class matrix.
for (const role of ['Developer', 'Operator', 'FieldAssessor']) {
  test(`non-admin internal role ${role} is internal but not Platform Admin`, () => {
    const actor = session([role], OPERATOR_TENANT);
    assert.equal(resolveConsolePrincipal(actor).experienceClass, 'internal_console');
    assert.equal(isPlatformAdminSession(actor), false);
    assert.equal(canAccessConsoleRoute('/admin/tenants', actor), false);
  });
}

test('non-admin internal roles cannot borrow gateway-backed human administration', () => {
  const bff = read('app/api/core/[...path]/route.ts');
  assert.match(bff, /isTenantAdminCorePath\(path\) &&[\s\S]*!isTenantAdminSession\(session\)[\s\S]*!isPlatformAdminSession\(session\)/);
  assert.match(bff, /Tenant Admin or Platform Admin authority required/);
});

test('Administrator is the canonical Platform Admin class', () => {
  assert.equal(isPlatformAdminSession(administrator), true);
  assert.equal(canAccessConsoleRoute('/admin/tenants', administrator), true);
});

test('Support semantics remain canonical Platform Admin', () => {
  assert.equal(isPlatformAdminSession(support), true);
  assert.equal(canAccessConsoleRoute('/admin/tenants', support), true);
});

test('unknown role fails closed', () => {
  const actor = session(['FutureSuperRole706'], TENANT_A);
  assert.equal(resolveConsolePrincipal(actor).experienceClass, 'unsupported');
  assertDenied(resolve(actor, [TENANT_A]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('empty roles fail closed', () => {
  const actor = session([], TENANT_A);
  assert.notEqual(resolveConsolePrincipal(actor).experienceClass, 'internal_console');
  assertDenied(resolve(actor, [TENANT_A]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('mixed known client and unknown role does not gain platform authority', () => {
  const actor = session(['tenant_admin', 'FutureRole706'], TENANT_A);
  assert.equal(resolveConsolePrincipal(actor).experienceClass, 'console_enabled_client');
  assert.equal(isPlatformAdminSession(actor), false);
  assert.equal(resolve(actor, [TENANT_A]).ok, true);
  assertDenied(resolve(actor, [TENANT_B]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('mixed Platform Admin and unknown role retains only recognized canonical policy', () => {
  const actor = session(['Administrator', 'FutureRole706'], OPERATOR_TENANT);
  assert.equal(isPlatformAdminSession(actor), true);
  assert.deepEqual(resolveConsolePrincipal(actor).roles, ['Administrator']);
});

test('unauthenticated authority resolution fails closed', () => {
  assertDenied(resolve(null, [TENANT_A]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('portal-only session cannot acquire Console tenant authority', () => {
  assertDenied(resolve(session(['Customer'], TENANT_A), [TENANT_A]), 403, 'TENANT_AUTHORITY_DENIED');
});

test('Tenant B admin cannot acquire Tenant A', () => {
  assertDenied(resolve(tenantBAdmin, [TENANT_A]), 403, 'TENANT_AUTHORITY_DENIED');
});

// Core/BFF route inventory and direct hidden-route controls.
for (const prefix of [
  'decisions',
  'ingest/assessment',
  'control-plane/readiness/frameworks',
  'field-assessment/engagements',
  'workforce/users',
  'portal/grants',
  'admin/identity/tenants',
  'admin/identity/invitations',
  'admin/tenants',
  'api/executive',
]) {
  test(`inventory marks ${prefix} as tenant scoped`, () => {
    const policy = CORE_API_POLICIES.find((entry) => entry.prefix === prefix);
    assert.ok(policy, `${prefix} must be inventoried`);
    assert.equal(policy.tenantScoped, true);
  });
}

test('tenant admin cannot reach global key administration', () => {
  assert.equal(canAccessCoreApiPath(['keys'], 'GET', tenantAAdmin), false);
  assert.equal(canAccessCoreApiPath(['keys'], 'POST', tenantAAdmin), false);
});

test('tenant admin cannot reach global connectors administration', () => {
  assert.equal(canAccessCoreApiPath(['admin', 'connectors'], 'GET', tenantAAdmin), false);
  assert.equal(canAccessCoreApiPath(['admin', 'connectors'], 'POST', tenantAAdmin), false);
});

test('tenant admin can reach own delegated tenant administration family', () => {
  assert.equal(canAccessCoreApiPath(['admin', 'tenants', TENANT_A, 'users'], 'GET', tenantAAdmin), true);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants', TENANT_A, 'users'], 'POST', tenantAAdmin), true);
});

test('platform-only tenant bootstrap has a positive BFF guard', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /function isPlatformAdminOnlyTenantPath/);
  assert.match(src, /path\[3\] === 'bootstrap-admin'/);
  assert.match(src, /!isPlatformAdminSession\(session\)/);
  assert.ok(src.indexOf('!isPlatformAdminSession(session)') < src.indexOf('resolveAuthorizedTenant(request'));
});

test('platform-only initial-admin invitation has a positive BFF guard', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /path\[3\] === 'invite-initial-admin'/);
  assert.match(src, /Platform Admin authority required/);
});

test('tenant creation remains Platform Admin only', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /if \(!isPlatformAdminSession\(session\)\)/);
  assert.ok(src.indexOf('!isPlatformAdminSession(session)') < src.indexOf('await req.json()'));
});

test('generic arbitrary email remains Platform Admin only', () => {
  const src = read('app/api/email/route.ts');
  assert.match(src, /if \(!isPlatformAdminSession\(session\)\)/);
  assert.ok(src.indexOf('!isPlatformAdminSession(session)') < src.indexOf('await req.json()'));
});

test('tenant registry does not global-fetch then filter for tenant admins', () => {
  const src = read('app/api/tenants/route.ts');
  const tenantBranch = src.indexOf('if (isTenantAdminSession(session))');
  const platformGuard = src.indexOf('if (!isPlatformAdminSession(session))');
  const registryCall = src.lastIndexOf('await getTenantRegistry()');
  assert.ok(tenantBranch > -1 && tenantBranch < platformGuard && platformGuard < registryCall);
  assert.match(src.slice(tenantBranch, platformGuard), /const tenants: TenantEntry\[] = \[/);
  assert.doesNotMatch(src.slice(tenantBranch, platformGuard), /getTenantRegistry\(/);
});

// Browser-controlled channels and field-assessment direct routes.
test('Core BFF rejects duplicate query keys with getAll rather than first-value collapse', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /searchParams\.getAll\('tenant_id'\)/);
  assert.doesNotMatch(src, /searchParams\.get\('tenant_id'\)/);
});

test('Core BFF canonicalizes tenant query before forwarding', () => {
  const src = read('app/api/core/[...path]/route.ts');
  const coreBuilder = src.match(/function buildCoreUrl[\s\S]*?\n\}/)?.[0] ?? '';
  const adminBuilder = src.match(/function buildAdminUrl[\s\S]*?\n\}/)?.[0] ?? '';
  for (const builder of [coreBuilder, adminBuilder]) {
    assert.match(builder, /query\.delete\('tenant_id'\)/);
    assert.match(builder, /query\.set\('tenant_id', tenantId\)/);
  }
});

test('JSON body tenant aliases are stripped before Core', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /tenant_id: _ignoredTenantId/);
  assert.match(src, /tenantId: _ignoredCamelTenantId/);
});

test('browser X-Tenant-ID is not copied into Core headers', () => {
  const src = read('app/api/core/[...path]/route.ts');
  const proxy = src.match(/async function proxyToCore[\s\S]*?\nasync function getAlignmentArtifact/)?.[0] ?? '';
  assert.match(proxy, /const headers = new Headers\(\)/);
  assert.doesNotMatch(proxy, /request\.headers\.get\(['"]x-tenant-id/i);
  assert.match(proxy, /headers\.set\('X-Tenant-ID', tenantId\)/);
});

for (const route of ['audio-url', 'transcribe']) {
  test(`${route} direct BFF route resolves session tenant credential`, () => {
    const src = read(`app/api/field-assessment/${route}/route.ts`);
    assert.match(src, /canAccessConsoleRoute\('\/field-assessment', session\)/);
    assert.match(src, /resolveTenantCredentialForConsoleRequest/);
    assert.match(src, /searchParams\.getAll\('tenant_id'\)/);
    assert.doesNotMatch(src, /const CORE_TENANT_ID/);
    assert.doesNotMatch(src, /const CORE_API_KEY/);
  });
}

test('direct field-assessment operator fallback validates configured tenant authority', () => {
  const resolver = read('lib/tenantRequestAuthority.ts');
  assert.match(resolver, /validateConfiguredOperatorAuthority/);
  assert.match(resolver, /operator-authority/);
  assert.match(resolver, /tenant_kind === 'internal_platform'/);
  assert.match(resolver, /operator_authority_allowed === true/);
  assert.ok(
    resolver.indexOf('validateConfiguredOperatorAuthority(') <
      resolver.lastIndexOf('return {\n      ok: true,'),
  );
});

test('field audio read forwards resolved tenant in query and header', () => {
  const src = read('app/api/field-assessment/audio-url/route.ts');
  assert.match(src, /encodeURIComponent\(tenantId\)/);
  assert.match(src, /'X-Tenant-ID': tenantId/);
});

test('field audio registration forwards resolved tenant in query and header', () => {
  const src = read('app/api/field-assessment/transcribe/route.ts');
  assert.match(src, /encodeURIComponent\(opts\.tenantId\)/);
  assert.match(src, /'X-Tenant-ID': opts\.tenantId/);
});

test('field assessment UI carries selected tenant to audio side routes', () => {
  const page = read('app/field-assessment/[engagementId]/page.tsx');
  const form = read('components/field-assessment/InterviewForm.tsx');
  assert.match(page, /tenantId=\{tenantId\}/);
  assert.match(page, /tenant_id=\$\{encodeURIComponent\(tenantId\)\}/);
  assert.match(form, /transcribe\$\{tenantQuery\}/);
});

test('invitation flow is tenant-independent and cannot borrow operator fallback', () => {
  const src = read('app/api/core/[...path]/route.ts');
  const inviteBranch = src.indexOf('if (isInvitationAcceptancePath(path))');
  const resolution = src.indexOf('const tenantResolution = resolveAuthorizedTenant');
  assert.ok(inviteBranch > -1 && inviteBranch < resolution);
  assert.match(src.slice(inviteBranch, resolution), /proxyToCore\(request, path, requestId, '', namedUserSub\)/);
});

// Actor-bound delegation and canonical Core membership proof.
test('delegation v3 binds actor subject and authority class into signed fields', () => {
  const bff = read('app/api/core/[...path]/route.ts');
  const core = readRepo('api/auth_scopes/resolution.py');
  assert.match(bff, /`v3\\n\$\{requestId\}\\n\$\{tenantId\}[\s\S]*\$\{actorSubject\}\\n\$\{actorAuthority\}`/);
  assert.match(core, /if version == "v3" and actor_authority not in/);
  assert.match(core, /request\.state\._delegated_actor_subject = actor_subject/);
  assert.match(core, /request\.state\._delegated_actor_authority = actor_authority/);
});

test('tenant-human gateway proof requires canonical active membership before tenant binding', () => {
  const core = readRepo('api/auth_scopes/resolution.py');
  const membership = core.indexOf('_verify_delegated_tenant_human_authority(request, requested)');
  const tenant = core.indexOf('_verify_admin_gateway_tenant(requested)');
  assert.ok(membership > 0);
  assert.ok(tenant > membership);
  assert.match(core, /str\(row\["role"\]\) == "tenant_admin"/);
  assert.match(core, /str\(row\["identity_binding_status"\]\) == "bound"/);
  assert.match(core, /str\(row\["principal_lifecycle_state"\]\) == "active"/);
});

test('delegated administrative BFF routes reject missing named actor authority', () => {
  const bff = read('app/api/core/[...path]/route.ts');
  assert.match(bff, /if \(!namedUserSub \|\| !actorAuthority\)/);
  assert.match(bff, /Delegated named actor authority required/);
});

test('Core proof binds method path tenant request id and expiry', () => {
  const core = readRepo('api/auth_scopes/resolution.py');
  for (const token of ['req_id', 'tenant_id', 'method', 'path', 'issued_at', 'expires_at']) {
    assert.match(core, new RegExp(token));
  }
  assert.match(core, /hmac\.compare_digest/);
});

test('Core verifies proof before tenant lifecycle and request-state binding', () => {
  const core = readRepo('api/auth_scopes/resolution.py');
  const proof = core.indexOf('_verify_delegation_proof(request, requested)');
  const tenant = core.indexOf('_verify_admin_gateway_tenant(requested)', proof);
  const state = core.indexOf('request.state.tenant_id = requested', proof);
  assert.ok(proof > -1 && proof < tenant && tenant < state);
});

test('Core tenant-admin authority requires active bound canonical membership', () => {
  const core = readRepo('api/tenant_admin_authority.py');
  assert.match(core, /if not row\.active/);
  assert.match(core, /str\(row\.role\) != "tenant_admin"/);
  assert.match(core, /str\(row\.identity_binding_status\) != "bound"/);
  assert.match(core, /row\.principal_id is None/);
});

test('Core tenant-admin denial is uniform and non-enumerating', () => {
  const core = readRepo('api/tenant_admin_authority.py');
  assert.match(core, /TENANT_ADMIN_DENIED/);
  assert.match(core, /def _denied\(\)/);
  assert.match(core, /status_code=403/);
});

// Persistence / credential census assertions.
test('field-assessment persistence has RLS and application tenant predicates', () => {
  const migrations = readRepo('api/db_migrations.py');
  const store = readRepo('services/field_assessment/store.py');
  assert.match(migrations, /"fa_engagements"/);
  assert.match(migrations, /"fa_field_observations"/);
  assert.match(store, /FaEngagement\.tenant_id == tenant_id/);
  assert.match(store, /FaScanResult\.tenant_id == tenant_id/);
});

test('identity membership and invitation persistence are in the RLS census', () => {
  const migrations = readRepo('api/db_migrations.py');
  assert.match(migrations, /"tenant_users"/);
  assert.match(migrations, /"tenant_invitations"/);
  assert.match(migrations, /"tenant_identity_audit_events"/);
});

test('tenant credentials have an explicit RLS isolation policy', () => {
  const migration = readRepo('migrations/postgres/0159_tenant_credentials.sql');
  assert.match(migration, /ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /tenant_credentials_tenant_isolation/);
  assert.match(migration, /current_setting\('app\.tenant_id'/);
});

test('credential reads and mutations use canonical authority tenant', () => {
  const core = readRepo('api/tenant_admin.py');
  assert.match(core, /ca\.list_credentials\([\s\S]*authority\.tenant_id/);
  assert.match(core, /ca\.get_credential\(engine, credential_id, authority\.tenant_id\)/);
  assert.match(core, /tenant_id=authority\.tenant_id/);
});

test('credential plaintext is emitted only by issue and rotate responses', () => {
  const core = readRepo('api/tenant_admin.py');
  const occurrences = [...core.matchAll(/\["plaintext_secret"\]/g)].length;
  assert.equal(occurrences, 2);
  assert.match(core, /Plaintext secret returned exactly once/);
});

test('dead primary TenantSwitcher implementation is removed', () => {
  assert.equal(fs.existsSync(path.join(__dirname, '..', 'components/common/TenantSwitcher.tsx')), false);
});

// Sentinel noninterference model: resolution itself makes foreign/operator data
// unreachable before fetch/persistence. Core repository tests cover the DB side.
test('Tenant A authority cannot select the BRAVO sentinel partition', () => {
  const partitions = { [TENANT_A]: ALPHA, [TENANT_B]: BRAVO, [OPERATOR_TENANT]: OPERATOR };
  const own = resolve(tenantAAdmin, [TENANT_A]);
  assert.equal(own.ok, true);
  assert.equal(partitions[own.tenantId], ALPHA);
  assert.notEqual(partitions[own.tenantId], BRAVO);
});

test('Tenant A authority cannot select the operator sentinel partition when context is missing', () => {
  const partitions = { [TENANT_A]: ALPHA, [TENANT_B]: BRAVO, [OPERATOR_TENANT]: OPERATOR };
  const missing = resolve(tenantAAdmin);
  assert.equal(missing.ok, true);
  assert.equal(partitions[missing.tenantId], ALPHA);
  assert.notEqual(partitions[missing.tenantId], OPERATOR);
});

test('denied foreign mutation has no selected persistence partition', () => {
  const result = resolve(tenantAAdmin, [TENANT_B]);
  assert.equal(result.ok, false);
  assert.equal(Object.hasOwn(result, 'tenantId'), false);
});

test('foreign and nonexistent denial bodies expose no tenant metadata', () => {
  for (const result of [
    resolve(tenantAAdmin, [TENANT_B]),
    resolve(tenantAAdmin, ['nonexistent-706']),
  ]) {
    assert.deepEqual(Object.keys(result).sort(), ['code', 'message', 'ok', 'status']);
    assert.doesNotMatch(JSON.stringify(result), /continental|nonexistent-706/i);
  }
});
