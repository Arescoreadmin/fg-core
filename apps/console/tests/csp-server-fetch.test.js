const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('CSP connect-src includes configured API and Auth0 origins without wildcards', async () => {
  const nextConfigPath = path.join(__dirname, '..', 'next.config.js');
  const originalApiUrl = process.env.NEXT_PUBLIC_API_URL;
  const originalIssuer = process.env.AUTH0_ISSUER_BASE_URL;

  process.env.NEXT_PUBLIC_API_URL = 'https://api-production-6d47.up.railway.app/v1';
  process.env.AUTH0_ISSUER_BASE_URL = 'dev-22nn3c7muqjk4tgu.us.auth0.com';

  try {
    delete require.cache[require.resolve(nextConfigPath)];
    const nextConfig = require(nextConfigPath);
    const headerRules = await nextConfig.headers();
    const csp = headerRules[0].headers.find((header) => header.key === 'Content-Security-Policy').value;

    assert.match(
      csp,
      /connect-src 'self' https:\/\/api-production-6d47\.up\.railway\.app https:\/\/dev-22nn3c7muqjk4tgu\.us\.auth0\.com/,
    );
    assert.doesNotMatch(csp, /\*\.auth0\.com/);
    assert.doesNotMatch(csp, /connect-src[^;]* [^']\*/);
  } finally {
    if (originalApiUrl === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = originalApiUrl;

    if (originalIssuer === undefined) delete process.env.AUTH0_ISSUER_BASE_URL;
    else process.env.AUTH0_ISSUER_BASE_URL = originalIssuer;

    delete require.cache[require.resolve(nextConfigPath)];
  }
});

test('server-side BFF helpers resolve absolute console URLs before fetch', () => {
  const coreApi = read('lib/coreApi.ts');
  const readinessApi = read('lib/readinessApi.ts');
  const fieldAssessmentApi = read('lib/fieldAssessmentApi.ts');

  assert.match(coreApi, /fetch\(await resolveConsoleUrl\(`\/api\/core\$\{path\}`\), \{/);
  assert.match(readinessApi, /fetch\(await resolveConsoleUrl\(url\), \{ cache: 'no-store' \}\)/);
  assert.match(fieldAssessmentApi, /fetch\(await resolveConsoleUrl\(`\$\{BASE\}\$\{path\}`\), \{/);
});

test('console URL helper keeps browser fetches relative and fails closed on the server', () => {
  const helper = read('lib/consoleUrl.ts');

  assert.match(helper, /if \(typeof window !== 'undefined'\)/);
  assert.match(helper, /return path;/);
  assert.match(helper, /new URL\(path, await resolveConsoleOrigin\(\)\)\.toString\(\)/);
  assert.match(helper, /Console origin is not configured\. Set CONSOLE_BASE_URL or NEXTAUTH_URL/);
});

test('logout uses a plain navigation anchor instead of a prefetched Next link', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  const signOutIndex = sidebar.indexOf('href="/api/auth/logout"');

  assert.notEqual(signOutIndex, -1, 'logout href must exist');

  const signOutSection = sidebar.slice(Math.max(0, signOutIndex - 80), signOutIndex + 160);
  assert.match(signOutSection, /<a[\s\S]*href="\/api\/auth\/logout"/);
  assert.doesNotMatch(signOutSection, /<Link[\s\S]*href="\/api\/auth\/logout"/);
});
