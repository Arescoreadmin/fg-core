'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('auth config sets an explicit enterprise session lifetime', () => {
  const src = read('auth.config.ts');
  assert.ok(src.includes('const DEFAULT_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;'));
  assert.ok(src.includes('AUTH_SESSION_MAX_AGE_SECONDS'));
  assert.ok(src.includes('maxAge: consoleSessionMaxAgeSeconds'));
  assert.ok(src.includes('jwt: {'));
  assert.doesNotMatch(src, /30 * 24 * 60 * 60/);
});

test('auth config bounds session env overrides', () => {
  const src = read('auth.config.ts');
  assert.ok(src.includes('15 * 60'));
  assert.ok(src.includes('24 * 60 * 60'));
  assert.ok(src.includes('AUTH_SESSION_UPDATE_AGE_SECONDS'));
  assert.ok(src.includes('5 * 60'));
  assert.ok(src.includes('60 * 60'));
});

test('full auth config reuses middleware-safe session policy', () => {
  const src = read('auth.ts');
  assert.ok(src.includes("import { authConfig } from './auth.config'"));
  assert.ok(src.includes('...authConfig'));
});

test('login requests interactive Auth0 login when starting a new local session', () => {
  const src = read('app/login/page.tsx');
  assert.ok(src.includes("signIn('auth0', { callbackUrl }, { prompt: 'login' })"));
});

