import { NextRequest, NextResponse } from 'next/server';
import { scanEmailAuth } from '@/lib/scanners/email-auth';
import { checkRateLimit, getClientIp } from '@/lib/rate-limit';
import { validateDomain } from '@/lib/validate-domain';

export const runtime = 'nodejs';
export const maxDuration = 30;

export async function POST(req: NextRequest) {
  // Rate limit before doing any work: every scan triggers outbound DNS and
  // network activity on the caller's behalf.
  const rate = checkRateLimit(getClientIp(req.headers));
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Try again shortly.' },
      { status: 429, headers: { 'Retry-After': String(rate.retryAfterSeconds) } }
    );
  }

  try {
    const { domain } = await req.json();

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
    }

    const cleaned = domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');

    const validation = validateDomain(cleaned);
    if (!validation.valid) {
      return NextResponse.json({ error: validation.reason }, { status: 400 });
    }

    const result = await scanEmailAuth(cleaned);
    return NextResponse.json(result);
  } catch (err) {
    console.error('Email auth scan error:', err);
    return NextResponse.json({ error: 'Scan failed' }, { status: 500 });
  }
}
