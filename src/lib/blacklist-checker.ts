/** Blacklist (DNSBL) checker with false-positive filtering - IPv4 only in v1 */

import { lookupDnsbl } from './dns-over-https';

export type Confidence = 'high' | 'medium' | 'low';

export interface BlacklistResult {
  name: string;
  host: string;
  listed: boolean;
  /** 'error' = the DNSBL query failed; NOT confirmed clean. Rendered as "Not checked" in the UI. */
  queryStatus: 'listed' | 'clean' | 'error';
  returnCodes: string[];
  confidence: Confidence;
  description: string;
  removalUrl: string;
  note?: string;
}

export interface BlacklistReport {
  ip: string;
  results: BlacklistResult[];
  isSharedHosting: boolean;
  sharedHostingNote?: string;
}

const BLACKLISTS = [
  { name: 'Spamhaus ZEN', host: 'zen.spamhaus.org', description: 'Industry-standard combined blocklist (SBL + XBL + PBL)', removalUrl: 'https://check.spamhaus.org/' },
  { name: 'Barracuda', host: 'b.barracudacentral.org', description: 'Barracuda Reputation Block List', removalUrl: 'https://www.barracudacentral.org/lookups/lookup-reputation' },
  { name: 'SpamCop', host: 'bl.spamcop.net', description: 'SpamCop Blocking List - real-time spam source detection', removalUrl: 'https://www.spamcop.net/bl.shtml' },
  { name: 'SORBS', host: 'dnsbl.sorbs.net', description: 'Spam and Open Relay Blocking System', removalUrl: 'https://www.sorbs.net/lookup/' },
  { name: 'UCEPROTECT L1', host: 'dnsbl-1.uceprotect.net', description: 'UCEPROTECT Level 1 - individual IP listings', removalUrl: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'Abuseat CBL', host: 'cbl.abuseat.org', description: 'Composite Blocking List - compromised host detection', removalUrl: 'https://www.abuseat.org/lookup.cgi' },
] as const;

// Known CDN/shared hosting IP ranges (CIDR prefixes for quick matching)
const SHARED_HOSTING_PREFIXES = [
  // Cloudflare
  '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',
  '172.64.', '172.65.', '172.66.', '172.67.',
  '103.21.244.', '103.22.200.', '103.31.4.',
  // AWS CloudFront
  '13.32.', '13.33.', '13.35.', '13.224.', '13.225.', '13.226.', '13.227.',
  '54.182.', '54.192.', '54.230.', '54.239.128.', '54.239.192.',
  '99.84.', '99.86.',
  '143.204.',
  '205.251.',
];

/** Spamhaus return code classification */
function classifySpamhausCode(code: string): { actionable: boolean; label: string } {
  // SBL (Spamhaus Block List) - actively sending spam
  if (code === '127.0.0.2' || code === '127.0.0.3') {
    return { actionable: true, label: 'SBL - spam source' };
  }
  // XBL (Exploits Block List) - compromised/exploited machines
  if (['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7'].includes(code)) {
    return { actionable: true, label: 'XBL - compromised host' };
  }
  // PBL (Policy Block List) - dynamic/residential IPs that shouldn't send mail directly
  if (code === '127.0.0.10' || code === '127.0.0.11') {
    return { actionable: false, label: 'PBL - policy block (not a spam listing)' };
  }
  return { actionable: true, label: 'Unknown Spamhaus code' };
}

function isSharedHostingIp(ip: string): boolean {
  return SHARED_HOSTING_PREFIXES.some((prefix) => ip.startsWith(prefix));
}

export async function checkBlacklists(ip: string): Promise<BlacklistReport> {
  const isShared = isSharedHostingIp(ip);

  const results = await Promise.allSettled(
    BLACKLISTS.map(async (bl) => {
      const { status: queryStatus, codes } = await lookupDnsbl(ip, bl.host);
      const listed = queryStatus === 'listed';

      let confidence: Confidence = 'medium';
      let note: string | undefined;

      if (bl.host === 'zen.spamhaus.org' && listed) {
        // Filter Spamhaus by return code
        const classifications = codes.map(classifySpamhausCode);
        const hasActionable = classifications.some((c) => c.actionable);
        if (!hasActionable) {
          // All codes are PBL - policy block, not a real listing
          confidence = 'low';
          note = classifications.map((c) => c.label).join(', ');
        } else {
          confidence = 'high';
          note = classifications.filter((c) => c.actionable).map((c) => c.label).join(', ');
        }
      } else if (bl.host === 'dnsbl-1.uceprotect.net' && listed) {
        // UCEPROTECT L1 is individual IPs (acceptable), but note it's aggressive
        confidence = 'medium';
        note = 'UCEPROTECT can be aggressive - verify with other lists';
      } else if (listed) {
        confidence = 'high';
      } else if (queryStatus === 'error') {
        confidence = 'low';
        note = 'Query failed - could not check this list (not confirmed clean)';
      }

      return {
        name: bl.name,
        host: bl.host,
        listed,
        queryStatus,
        returnCodes: codes,
        confidence,
        description: bl.description,
        removalUrl: bl.removalUrl,
        note,
      } satisfies BlacklistResult;
    }),
  );

  const resolved: BlacklistResult[] = results.map((r, i) =>
    r.status === 'fulfilled'
      ? r.value
      : {
          name: BLACKLISTS[i].name,
          host: BLACKLISTS[i].host,
          listed: false,
          queryStatus: 'error' as const,
          returnCodes: [],
          confidence: 'low' as Confidence,
          description: BLACKLISTS[i].description,
          removalUrl: BLACKLISTS[i].removalUrl,
          note: 'Query failed - could not check this list',
        },
  );

  return {
    ip,
    results: resolved,
    isSharedHosting: isShared,
    sharedHostingNote: isShared
      ? 'This IP belongs to a CDN or shared hosting provider. Blacklist results may reflect other tenants, not your domain specifically.'
      : undefined,
  };
}
