/**
 * GET /api/assessment/payment-status/[id]
 *
 * Public BFF route — no session required. Called by the activation page
 * (/assessment/activate) to check whether a Stripe payment has been confirmed
 * before offering the account-creation CTA.
 *
 * Proxies to the Core API GET /ingest/assessment/{id}/payment-status which is
 * also public (self-contained; no content returned, only payment_status).
 */
import { NextRequest, NextResponse } from 'next/server';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const id = (await params).id ?? '';
  if (!id || !/^[a-zA-Z0-9_-]{8,}$/.test(id)) {
    return NextResponse.json({ error: 'Invalid assessment id' }, { status: 400 });
  }

  try {
    const upstream = await fetch(
      `${CORE_API_URL}/ingest/assessment/${encodeURIComponent(id)}/payment-status`,
      { cache: 'no-store' },
    );
    const body = await upstream.text();
    return new NextResponse(body, {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  } catch {
    return NextResponse.json({ error: 'Service unavailable' }, { status: 503 });
  }
}
