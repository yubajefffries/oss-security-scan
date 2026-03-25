import { NextRequest, NextResponse } from 'next/server';
import { scanHeaders } from '@/lib/scanners/headers';
import { validateDomain } from '@/lib/validate-domain';

export const runtime = 'nodejs';
export const maxDuration = 30;

export async function POST(req: NextRequest) {
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

    const result = await scanHeaders(cleaned);
    return NextResponse.json(result);
  } catch (err) {
    console.error('Headers scan error:', err);
    return NextResponse.json({ error: 'Scan failed' }, { status: 500 });
  }
}
