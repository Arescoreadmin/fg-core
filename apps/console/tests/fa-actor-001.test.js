/* FA-ACTOR-001 Console BFF delegation contract. */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const ROUTE = fs.readFileSync(
  path.join(ROOT, 'app/api/core/[...path]/route.ts'),
  'utf8',
);

test('Field Assessment mutations use the existing delegated actor path', () => {
  assert.match(ROUTE, /function isFieldAssessmentMutationPath\(/);
  assert.match(ROUTE, /path\[0\] === 'field-assessment'/);
  assert.match(ROUTE, /const requiresDelegatedActor = isTenantAdminPath \|\| isFieldAssessmentMutation/);
  assert.match(ROUTE, /if \(requiresDelegatedActor\)/);
});

test('Field Assessment delegation binds request identity and authority class', () => {
  assert.match(ROUTE, /headers\.set\('X-FG-Named-User-Sub', namedUserSub\)/);
  assert.match(ROUTE, /headers\.set\('X-FG-Actor-Authority', actorAuthority\)/);
  assert.match(ROUTE, /createDelegationProof\(/);
  assert.match(ROUTE, /headers\.set\('X-FG-Delegation-Proof', delegation\.proof\)/);
});

test('Field Assessment never falls back to tenant credential for mutations', () => {
  const helperStart = ROUTE.indexOf('function isFieldAssessmentMutationPath');
  const proxyStart = ROUTE.indexOf('async function proxyToCore');
  const proxy = ROUTE.slice(proxyStart);
  assert.ok(helperStart >= 0);
  assert.match(proxy, /const requiresDelegatedActor = isTenantAdminPath \|\| isFieldAssessmentMutation/);
  assert.match(proxy, /const coreAuth = await resolveCoreAuth\(tenantId, requestId\)/);
  assert.ok(
    proxy.indexOf('const coreAuth = await resolveCoreAuth(tenantId, requestId)') >
      proxy.indexOf('if (requiresDelegatedActor)'),
  );
});
