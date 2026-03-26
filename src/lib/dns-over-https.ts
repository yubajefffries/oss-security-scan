/** DNS-over-HTTPS query utilities using Cloudflare + Google fallback */

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DnsAnswer[];
  Authority?: DnsAnswer[];
  Comment?: string;
}

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
}

export interface DnsLookupResult {
  records: DnsRecord[];
  error?: string;
}

const RECORD_TYPE_MAP: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
};

function sanitizeDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  // Strip protocol
  domain = domain.replace(/^https?:\/\//, '');
  // Strip path, query, fragment
  domain = domain.split('/')[0].split('?')[0].split('#')[0];
  // Strip port
  domain = domain.split(':')[0];
  // Strip trailing dot
  domain = domain.replace(/\.$/, '');
  return domain;
}

export function isValidDomain(input: string): boolean {
  const domain = sanitizeDomain(input);
  if (!domain || domain.length > 253) return false;
  // Must have at least one dot and valid chars
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/.test(domain);
}

async function dohFetch(domain: string, type: string): Promise<DohResponse> {
  const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  const googleUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;

  try {
    const res = await fetch(cfUrl, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return res.json();
  } catch {
    // Cloudflare failed, try Google
  }

  const res = await fetch(googleUrl, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`DNS lookup failed (${res.status})`);
  return res.json();
}

function parseDohResponse(response: DohResponse, requestedType: string): DnsRecord[] {
  if (!response.Answer) return [];
  return response.Answer.map((a) => ({
    name: a.name.replace(/\.$/, ''),
    type: RECORD_TYPE_MAP[a.type] ?? String(a.type),
    ttl: a.TTL,
    value: a.data.replace(/^"|"$/g, ''), // Strip TXT record quotes
  })).filter((r) => requestedType === 'ANY' || r.type === requestedType);
}

export async function queryDns(domain: string, type: string): Promise<DnsLookupResult> {
  const clean = sanitizeDomain(domain);
  if (!clean) return { records: [], error: 'Invalid domain' };
  try {
    const response = await dohFetch(clean, type);
    return { records: parseDohResponse(response, type) };
  } catch (err) {
    return { records: [], error: err instanceof Error ? err.message : 'Lookup failed' };
  }
}

export async function lookupAll(domain: string): Promise<Record<string, DnsLookupResult>> {
  const clean = sanitizeDomain(domain);
  const types = ['A', 'AAAA', 'MX', 'TXT', 'NS'] as const;
  const results = await Promise.allSettled(types.map((t) => queryDns(clean, t)));

  const out: Record<string, DnsLookupResult> = {};
  types.forEach((type, i) => {
    const result = results[i];
    out[type] = result.status === 'fulfilled'
      ? result.value
      : { records: [], error: 'Lookup failed' };
  });
  return out;
}

export async function lookupSpf(domain: string): Promise<DnsRecord | null> {
  const { records } = await queryDns(domain, 'TXT');
  return records.find((r) => r.value.startsWith('v=spf1')) ?? null;
}

export async function lookupDmarc(domain: string): Promise<DnsRecord | null> {
  const clean = sanitizeDomain(domain);
  const { records } = await queryDns(`_dmarc.${clean}`, 'TXT');
  return records.find((r) => r.value.startsWith('v=DMARC1')) ?? null;
}

export async function lookupDkim(domain: string, selector: string): Promise<DnsRecord | null> {
  const clean = sanitizeDomain(domain);
  const { records } = await queryDns(`${selector}._domainkey.${clean}`, 'TXT');
  return records.find((r) => r.value.includes('v=DKIM1') || r.value.includes('p=')) ?? null;
}

/** Reverse IP octets for DNSBL queries (e.g. 1.2.3.4 -> 4.3.2.1) */
export function reverseIp(ip: string): string {
  return ip.split('.').reverse().join('.');
}

/** Query a DNSBL - returns A record values if listed, empty array if clean */
export async function lookupDnsbl(ip: string, blacklistHost: string): Promise<string[]> {
  const reversed = reverseIp(ip);
  const query = `${reversed}.${blacklistHost}`;
  try {
    const response = await dohFetch(query, 'A');
    if (!response.Answer || response.Answer.length === 0) return [];
    return response.Answer.map((a) => a.data);
  } catch {
    return [];
  }
}
