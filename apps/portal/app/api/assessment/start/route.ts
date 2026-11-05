/**
 * POST /api/assessment/start
 *
 * Public BFF endpoint — no session required. Called from the self-service
 * assessment intake form at /assessment.
 *
 * Flow:
 *   1. POST /ingest/assessment/orgs on Core API → org + assessment_id
 *   2. POST /ingest/assessment/{id}/checkout on Core API → Stripe checkout URL
 *   3. Return { checkout_url } to the browser for redirect.
 *
 * Rate-limited (5 intakes per IP per minute) to prevent lead spam.
 */
import { NextRequest, NextResponse } from 'next/server';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY || '';

const _rl = new Map<string, { count: number; resetAt: number }>();
const RL_WINDOW_MS = 60_000;
const RL_MAX = 5;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = _rl.get(ip);
  if (!entry || now >= entry.resetAt) {
    _rl.set(ip, { count: 1, resetAt: now + RL_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= RL_MAX;
}

export async function POST(req: NextRequest) {
  if (!CORE_API_KEY) {
    return NextResponse.json({ error: 'Service not configured' }, { status: 503 });
  }

  const ip =
    req.headers.get('x-real-ip') ||
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown';

  if (!checkRateLimit(ip)) {
    return NextResponse.json({ error: 'Too many requests. Please try again shortly.' }, { status: 429 });
  }

  let body: { name?: string; email?: string; industry?: string; employee_count?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const name = (body.name ?? '').trim();
  const email = (body.email ?? '').trim();

  if (!name) return NextResponse.json({ error: 'Organization name is required' }, { status: 400 });
  if (!email) return NextResponse.json({ error: 'Email is required' }, { status: 400 });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
  }

  // 1. Create org + assessment (lead namespace — no tenant yet)
  let assessmentId: string;
  try {
    const orgResp = await fetch(`${CORE_API_URL}/ingest/assessment/orgs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': CORE_API_KEY },
      body: JSON.stringify({
        name,
        email,
        industry: (body.industry || 'other').toLowerCase(),
        employee_count: body.employee_count || '',
      }),
      cache: 'no-store',
    });
    if (!orgResp.ok) {
      const err = await orgResp.text().catch(() => '');
      console.error('[assessment/start] org create failed:', orgResp.status, err);
      return NextResponse.json({ error: 'Could not create assessment. Please try again.' }, { status: 502 });
    }
    const data = (await orgResp.json()) as { assessment_id: string };
    assessmentId = data.assessment_id;
  } catch (err) {
    console.error('[assessment/start] org create error:', err);
    return NextResponse.json({ error: 'Service unavailable. Please try again.' }, { status: 503 });
  }

  // 2. Initiate Stripe checkout
  try {
    const checkoutResp = await fetch(
      `${CORE_API_URL}/ingest/assessment/${encodeURIComponent(assessmentId)}/checkout`,
      {
        method: 'POST',
        headers: { 'X-API-Key': CORE_API_KEY },
        cache: 'no-store',
      },
    );
    if (!checkoutResp.ok) {
      const err = await checkoutResp.text().catch(() => '');
      console.error('[assessment/start] checkout failed:', checkoutResp.status, err);
      return NextResponse.json({ error: 'Could not initiate checkout. Please try again.' }, { status: 502 });
    }
    const { checkout_url, already_paid } = (await checkoutResp.json()) as {
      checkout_url: string | null;
      already_paid?: boolean;
    };
    if (already_paid || !checkout_url) {
      return NextResponse.json({ error: 'Assessment already paid' }, { status: 409 });
    }
    return NextResponse.json({ checkout_url });
  } catch (err) {
    console.error('[assessment/start] checkout error:', err);
    return NextResponse.json({ error: 'Service unavailable. Please try again.' }, { status: 503 });
  }
}
