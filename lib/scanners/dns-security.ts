// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import dns from 'dns/promises';

import { pinnedRequest } from '../pinned-http';
import { pickConnectAddress, resolveAndValidate } from '../validate-domain';

export type DnsSecurityCheckStatus = 'pass' | 'warning' | 'info' | 'error';

export interface DnssecCheck {
  status: DnsSecurityCheckStatus;
  /** DS record present at the parent zone (the delegation is signed) */
  dsFound: boolean;
  /** DS present AND the validating resolver set the AD flag for the zone */
  validated: boolean;
}

export interface CaaCheck {
  status: DnsSecurityCheckStatus;
  found: boolean;
  records: string[];
}

export interface BimiCheck {
  status: DnsSecurityCheckStatus;
  found: boolean;
  record?: string;
}

export interface MtaStsCheck {
  status: DnsSecurityCheckStatus;
  txtFound: boolean;
  txtRecord?: string;
  policyFetched: boolean;
  mode?: 'enforce' | 'testing' | 'none';
  policyIssues: string[];
}

export interface DnsSecurityResult {
  status: 'pass' | 'warning' | 'critical' | 'error';
  dnssec: DnssecCheck;
  caa: CaaCheck;
  bimi: BimiCheck;
  mtaSts: MtaStsCheck;
  issues: string[];
  summary: string;
}

/**
 * Joins the 255-character TXT chunks of each record before matching.
 * A naive .flat() treats each chunk as its own record, truncating any
 * record longer than 255 characters.
 */
function joinTxtChunks(records: string[][]): string[] {
  return records.map((chunks) => chunks.join(''));
}

function isNoData(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return code === 'ENOTFOUND' || code === 'ENODATA';
}

/**
 * DNSSEC check via DNS-over-HTTPS.
 *
 * Known limitation: Node's built-in resolver (c-ares) has no DS or DNSKEY
 * rrtype — dns.resolve() rejects them and resolveAny() omits DNSSEC types —
 * so this is the one check that goes through Cloudflare's DoH JSON API
 * instead of dns/promises. It queries a fixed, trusted resolver endpoint
 * only, never the scanned host, so the SSRF/IP-pinning guard does not apply.
 *
 * DS presence at the parent proves the delegation is signed; the AD
 * (Authenticated Data) flag on an ordinary query proves the chain actually
 * validates. The AD flag alone is NOT enough — unsigned zones also get
 * AD=true on the validated *denial* of a DS record.
 */
async function checkDnssec(domain: string): Promise<DnssecCheck> {
  const query = async (type: string) => {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) throw new Error(`DoH lookup failed (${res.status})`);
    return res.json() as Promise<{ Status: number; AD?: boolean; Answer?: Array<{ type: number }> }>;
  };

  try {
    const [ds, soa] = await Promise.all([query('DS'), query('SOA')]);
    const dsFound = (ds.Answer ?? []).some((a) => a.type === 43); // rrtype 43 = DS
    const validated = dsFound && soa.AD === true;
    return { status: validated ? 'pass' : 'warning', dsFound, validated };
  } catch {
    return { status: 'error', dsFound: false, validated: false };
  }
}

async function checkCaa(domain: string): Promise<CaaCheck> {
  try {
    const records = await dns.resolveCaa(domain);
    const formatted = records.map((rec) => {
      // A CAA record object has `critical` (and on some Node versions a
      // `type: 'CAA'` marker) plus exactly one tag property
      // (issue / issuewild / iodef / ...).
      const [tag, value] =
        Object.entries(rec).find(([key]) => key !== 'critical' && key !== 'type') ?? ['?', ''];
      return `${rec.critical} ${tag} "${value}"`;
    });
    return { status: formatted.length > 0 ? 'pass' : 'warning', found: formatted.length > 0, records: formatted };
  } catch (err) {
    // No CAA record is an authoritative answer, not a lookup failure.
    if (isNoData(err)) return { status: 'warning', found: false, records: [] };
    return { status: 'error', found: false, records: [] };
  }
}

async function checkBimi(domain: string): Promise<BimiCheck> {
  try {
    const records = await dns.resolveTxt(`default._bimi.${domain}`);
    const record = joinTxtChunks(records).find((r) => r.toLowerCase().startsWith('v=bimi1'));
    // BIMI is a branding nicety, not a security control — absence is informational.
    return record ? { status: 'pass', found: true, record } : { status: 'info', found: false };
  } catch (err) {
    if (isNoData(err)) return { status: 'info', found: false };
    return { status: 'error', found: false };
  }
}

async function checkMtaSts(domain: string): Promise<MtaStsCheck> {
  let txtRecord: string | undefined;
  try {
    const records = await dns.resolveTxt(`_mta-sts.${domain}`);
    txtRecord = joinTxtChunks(records).find((r) => r.toLowerCase().startsWith('v=stsv1'));
  } catch {
    // No record / lookup failure both fall through to "not found" below.
  }

  if (!txtRecord) {
    return { status: 'warning', txtFound: false, policyFetched: false, policyIssues: [] };
  }

  // The policy file lives at a well-known HTTPS URL on the mta-sts subdomain.
  // Same SSRF rules as every other outbound connection: validate + IP-pin.
  const policyHost = `mta-sts.${domain}`;
  const policyIssues: string[] = [];
  const guard = await resolveAndValidate(policyHost);
  if (!guard.valid) {
    policyIssues.push(`MTA-STS policy file could not be fetched: ${guard.reason}`);
    return { status: 'warning', txtFound: true, txtRecord, policyFetched: false, policyIssues };
  }

  try {
    const response = await pinnedRequest(
      new URL(`https://${policyHost}/.well-known/mta-sts.txt`),
      pickConnectAddress(guard.addresses),
      { method: 'GET', timeoutMs: 10000 }
    );
    if (response.statusCode !== 200) {
      policyIssues.push(`MTA-STS policy file returned HTTP ${response.statusCode} - senders will ignore the policy.`);
      return { status: 'warning', txtFound: true, txtRecord, policyFetched: false, policyIssues };
    }

    // Policy format (RFC 8461): "key: value" lines.
    const fields = new Map<string, string>();
    for (const line of response.body.split(/\r?\n/)) {
      const idx = line.indexOf(':');
      if (idx > 0) fields.set(line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim());
    }

    if (fields.get('version')?.toLowerCase() !== 'stsv1') {
      policyIssues.push('MTA-STS policy file is missing "version: STSv1".');
    }
    if (!fields.has('max_age')) {
      policyIssues.push('MTA-STS policy file is missing "max_age".');
    }

    const rawMode = fields.get('mode')?.toLowerCase();
    const mode = rawMode === 'enforce' || rawMode === 'testing' || rawMode === 'none' ? rawMode : undefined;
    if (!mode) {
      policyIssues.push('MTA-STS policy file has a missing or invalid "mode".');
    } else if (mode === 'testing') {
      policyIssues.push('MTA-STS mode is "testing" - failures are reported but delivery is not protected. Move to "enforce" when ready.');
    } else if (mode === 'none') {
      policyIssues.push('MTA-STS mode is "none" - the policy is published but disabled.');
    }

    const status: DnsSecurityCheckStatus = mode === 'enforce' && policyIssues.length === 0 ? 'pass' : 'warning';
    return { status, txtFound: true, txtRecord, policyFetched: true, mode, policyIssues };
  } catch {
    policyIssues.push('MTA-STS policy file could not be fetched (connection failed or timed out).');
    return { status: 'warning', txtFound: true, txtRecord, policyFetched: false, policyIssues };
  }
}

export async function scanDnsSecurity(domain: string): Promise<DnsSecurityResult> {
  const [dnssec, caa, bimi, mtaSts] = await Promise.all([
    checkDnssec(domain),
    checkCaa(domain),
    checkBimi(domain),
    checkMtaSts(domain),
  ]);

  const issues: string[] = [];
  if (dnssec.status === 'error') {
    issues.push('DNSSEC status could not be determined (DoH lookup failed).');
  } else if (!dnssec.validated) {
    issues.push(
      dnssec.dsFound
        ? 'A DS record exists but the DNSSEC chain did not validate - broken signatures can make the domain unresolvable for validating resolvers.'
        : 'DNSSEC is not enabled. DNS responses for this domain can be forged (cache poisoning). Enable DNSSEC at your registrar/DNS host.'
    );
  }
  if (caa.status === 'error') {
    issues.push('CAA lookup failed - could not determine certificate issuance policy.');
  } else if (!caa.found) {
    issues.push('No CAA record found. Any certificate authority can issue certificates for this domain - a CAA record restricts issuance to CAs you approve.');
  }
  if (!bimi.found && bimi.status !== 'error') {
    issues.push('No BIMI record found (optional). BIMI shows your logo next to authenticated email in supporting inboxes - requires DMARC at enforcement.');
  }
  if (!mtaSts.txtFound) {
    issues.push('No MTA-STS record found. Without it, an active attacker can downgrade inbound SMTP connections to your mail servers to plaintext.');
  }
  issues.push(...mtaSts.policyIssues);

  // Status roll-up: BIMI is informational and never degrades the result.
  const securityChecks = [dnssec, caa, mtaSts];
  const status: DnsSecurityResult['status'] = securityChecks.every((c) => c.status === 'error')
    ? 'error'
    : securityChecks.some((c) => c.status === 'warning' || c.status === 'error')
    ? 'warning'
    : 'pass';

  const summaries: Record<DnsSecurityResult['status'], string> = {
    pass: 'DNSSEC, CAA, and MTA-STS are all configured. Your DNS integrity, certificate issuance, and mail transport are well protected.',
    warning: 'Some DNS security controls are missing or incomplete. Each issue below is a straightforward DNS or hosting change.',
    critical: 'DNS security has critical gaps that need immediate attention.',
    error: 'Could not complete the DNS security scan.',
  };

  return { status, dnssec, caa, bimi, mtaSts, issues, summary: summaries[status] };
}
