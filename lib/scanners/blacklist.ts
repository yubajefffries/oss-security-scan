// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import dns, { Resolver } from 'dns/promises';

/**
 * DNSBL queries go through a dedicated resolver instance backed by the
 * machine's own configured DNS servers. Public DoH resolvers (Cloudflare,
 * Google) are blocked or rate-limited by Spamhaus and Barracuda, which
 * silently under-reports listings - a direct resolver query is
 * authoritative. Timeouts are capped so one dead DNSBL can't stall the scan.
 */
const dnsblResolver = new Resolver({ timeout: 5000, tries: 2 });

export interface BlacklistListing {
  list: string;
  ip: string;
  description: string;
  /** Spamhaus-specific: which sub-list triggered (SBL, XBL, PBL, CSS) */
  sublists: string[];
  /** 'critical' = active spam/malware source; 'warning' = policy/shared IP (PBL) */
  severity: 'critical' | 'warning';
  explanation: string;
}

export interface BlacklistResult {
  status: 'pass' | 'warning' | 'critical' | 'error';
  mxHosts: string[];
  mxIPs: string[];
  listedOn: BlacklistListing[];
  checkedLists: Array<{ name: string; description: string }>;
  issues: string[];
  summary: string;
  /** True if all hits are PBL-only (shared provider IPs — expected, not actionable) */
  onlyPBL: boolean;
  /**
   * DNSBL queries that errored (timeout / SERVFAIL / network) - their status
   * is UNKNOWN, not confirmed clean. Surfaced via issues[] and rendered as
   * "not checked" (never "clean") by UI consumers.
   */
  unverified: Array<{ list: string; ip: string }>;
}

const DNSBL_LISTS = [
  {
    host: 'zen.spamhaus.org',
    name: 'Spamhaus ZEN',
    description: 'Industry-leading composite blocklist combining SBL (spam sources), XBL (malware/exploits), and PBL (policy — shared/dynamic IPs). Used by most major email providers.',
  },
  {
    host: 'b.barracudacentral.org',
    name: 'Barracuda BRBL',
    description: 'Widely used by corporate email filters and Barracuda security appliances.',
  },
  {
    host: 'bl.spamcop.net',
    name: 'SpamCop',
    description: 'Real-time blocklist built from user spam reports.',
  },
  {
    host: 'dnsbl.sorbs.net',
    name: 'SORBS',
    description: 'Spam and Open Relay Blocking System.',
  },
];

/**
 * Spamhaus ZEN return code → sub-list mapping.
 * The DNS lookup returns a 127.0.0.x address indicating which sub-list matched.
 */
const SPAMHAUS_CODES: Record<string, { sublist: string; severity: 'critical' | 'warning'; explanation: string }> = {
  '127.0.0.2':  { sublist: 'SBL',     severity: 'critical', explanation: 'This IP is a confirmed spam source on the Spamhaus Block List. Emails from this server are likely being rejected by most providers.' },
  '127.0.0.3':  { sublist: 'CSS',     severity: 'critical', explanation: 'Listed for compromised or snowshoe spam activity. Your mail server may have been hacked or is sending bulk unsolicited email.' },
  '127.0.0.4':  { sublist: 'XBL/CBL', severity: 'critical', explanation: 'This IP is on the Exploits Block List — it\'s sending spam via malware or an open proxy. Likely indicates a compromised machine on your network.' },
  '127.0.0.5':  { sublist: 'XBL/CBL', severity: 'critical', explanation: 'This IP is on the Exploits Block List — it\'s sending spam via malware or an open proxy. Likely indicates a compromised machine on your network.' },
  '127.0.0.6':  { sublist: 'XBL/CBL', severity: 'critical', explanation: 'This IP is on the Exploits Block List — it\'s sending spam via malware or an open proxy. Likely indicates a compromised machine on your network.' },
  '127.0.0.7':  { sublist: 'XBL/CBL', severity: 'critical', explanation: 'This IP is on the Exploits Block List — it\'s sending spam via malware or an open proxy. Likely indicates a compromised machine on your network.' },
  '127.0.0.9':  { sublist: 'SBL-CSS', severity: 'critical', explanation: 'Listed as a compromised or snowshoe spam source. Your email infrastructure needs immediate attention.' },
  '127.0.0.10': { sublist: 'PBL',     severity: 'warning',  explanation: 'This IP is on the Policy Block List (PBL). This sub-list covers IPs that should route email through a proper mail server rather than sending directly — it is commonly triggered by shared provider IPs (Google Workspace, Microsoft 365). This is usually not actionable and does not mean your emails are being blocked.' },
  '127.0.0.11': { sublist: 'PBL',     severity: 'warning',  explanation: 'This IP is on the Policy Block List (PBL). PBL listings are normal for shared mail server IPs (Google, Microsoft, etc.) and are maintained by ISPs to prevent direct-send abuse. If you\'re using a major email provider, this is expected and typically not a deliverability issue.' },
};

/**
 * Spamhaus error-range return codes (127.255.255.0/24): the query was
 * refused, NOT answered from listing data. 252 = typing error / wrong
 * query, 253 = query blocked, 254 = query sent via a public/open resolver.
 * These mean the check could not be performed and must be treated as
 * unverified - never as clean, and never as a listing.
 */
const SPAMHAUS_ERROR_CODES = new Set(['127.255.255.252', '127.255.255.253', '127.255.255.254']);

async function reverseIP(ip: string): Promise<string> {
  return ip.split('.').reverse().join('.');
}

type DnsblOutcome =
  | { outcome: 'listed'; responseCodes: string[] }
  | { outcome: 'clean' }
  | { outcome: 'error' };

async function checkDNSBL(
  ip: string,
  list: (typeof DNSBL_LISTS)[number]
): Promise<DnsblOutcome> {
  try {
    const reversed = await reverseIP(ip);
    const responseCodes = await dnsblResolver.resolve4(`${reversed}.${list.host}`);
    // Strip Spamhaus error-range codes: they signal a refused/blocked query,
    // not a listing. A response with only error codes is unverified.
    const listingCodes = responseCodes.filter((code) => !SPAMHAUS_ERROR_CODES.has(code));
    if (listingCodes.length === 0) return { outcome: 'error' };
    return { outcome: 'listed', responseCodes: listingCodes };
  } catch (err) {
    // Only NXDOMAIN/no-data is an authoritative "not listed". Timeouts,
    // SERVFAIL, refusals etc. mean the lookup is UNDETERMINABLE and must
    // not be reported as clean.
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') return { outcome: 'clean' };
    return { outcome: 'error' };
  }
}

async function getMXIPs(domain: string): Promise<{ hosts: string[]; ips: string[] }> {
  try {
    const mxRecords = await dns.resolveMx(domain);
    const hosts = mxRecords
      .sort((a, b) => a.priority - b.priority)
      .slice(0, 3)
      .map((r) => r.exchange);

    const ipResults = await Promise.allSettled(
      hosts.map((host) => dns.resolve4(host))
    );

    const ips: string[] = [];
    for (const result of ipResults) {
      if (result.status === 'fulfilled') {
        ips.push(...result.value.slice(0, 1));
      }
    }

    return { hosts, ips };
  } catch {
    return { hosts: [], ips: [] };
  }
}

export async function scanBlacklist(domain: string): Promise<BlacklistResult> {
  const { hosts: mxHosts, ips: mxIPs } = await getMXIPs(domain);

  if (mxIPs.length === 0) {
    return {
      status: 'warning',
      mxHosts,
      mxIPs: [],
      listedOn: [],
      checkedLists: DNSBL_LISTS.map((l) => ({ name: l.name, description: l.description })),
      issues: ['No mail server IPs found for this domain. Email may not be configured.'],
      summary: 'Could not find mail server IPs to check blacklist status.',
      onlyPBL: false,
      unverified: [],
    };
  }

  const listedOn: BlacklistListing[] = [];
  const unverified: Array<{ list: string; ip: string }> = [];

  await Promise.all(
    mxIPs.flatMap((ip) =>
      DNSBL_LISTS.map(async (list) => {
        const result = await checkDNSBL(ip, list);
        if (result.outcome === 'error') {
          unverified.push({ list: list.name, ip });
          return;
        }
        if (result.outcome === 'clean') return;

        if (list.name === 'Spamhaus ZEN') {
          // Decode which sub-lists triggered
          const sublists: string[] = [];
          let severity: 'critical' | 'warning' = 'warning';
          let explanation = 'This IP was found on Spamhaus ZEN.';

          for (const code of result.responseCodes) {
            const info = SPAMHAUS_CODES[code];
            if (info) {
              if (!sublists.includes(info.sublist)) sublists.push(info.sublist);
              if (info.severity === 'critical') severity = 'critical';
              explanation = info.explanation; // Use the most specific explanation
            }
          }

          listedOn.push({
            list: list.name,
            ip,
            description: list.description,
            sublists,
            severity,
            explanation,
          });
        } else {
          listedOn.push({
            list: list.name,
            ip,
            description: list.description,
            sublists: [],
            severity: 'critical',
            explanation: `IP ${ip} is listed on ${list.name}. Your emails may be blocked or sent to spam by servers using this blocklist.`,
          });
        }
      })
    )
  );

  const criticalListings = listedOn.filter((l) => l.severity === 'critical');
  const warningListings  = listedOn.filter((l) => l.severity === 'warning');
  const onlyPBL = listedOn.length > 0 && criticalListings.length === 0;

  const issues = listedOn.map((l) => {
    const sublistLabel = l.sublists.length > 0 ? ` [${l.sublists.join(', ')}]` : '';
    if (l.severity === 'warning') {
      return `IP ${l.ip} is on ${l.list}${sublistLabel} — this is a policy listing (PBL), common for shared mail providers. Usually not actionable.`;
    }
    return `IP ${l.ip} is listed on ${l.list}${sublistLabel}. Your emails may be blocked or sent to spam.`;
  });

  for (const u of unverified) {
    issues.push(`Could not check ${u.list} for IP ${u.ip} (query failed) - status unknown, not confirmed clean.`);
  }

  const totalChecks = mxIPs.length * DNSBL_LISTS.length;

  let status: BlacklistResult['status'];
  if (listedOn.length === 0) {
    // Never report "Clean" when queries errored: an unreachable DNSBL is
    // undeterminable, not a confirmed-clean result.
    status =
      unverified.length === 0
        ? 'pass'
        : unverified.length >= totalChecks
        ? 'error'
        : 'warning';
  } else if (criticalListings.length >= 2) {
    status = 'critical';
  } else if (criticalListings.length === 1) {
    status = 'warning';
  } else {
    // Only PBL / policy warnings
    status = 'warning';
  }

  const summaries: Record<BlacklistResult['status'], string> = {
    pass: `Your mail server IPs are clean across all ${DNSBL_LISTS.length} blocklists checked. Email deliverability looks good.`,
    warning: onlyPBL
      ? 'Your mail server IP appears on the Spamhaus PBL (Policy Block List). This is common for domains using Google Workspace or Microsoft 365 and is usually not a deliverability problem — but worth monitoring.'
      : 'One of your mail server IPs appears on a blocklist. Some emails may be filtered as spam.',
    critical: `${criticalListings.length} serious blocklist listing${criticalListings.length !== 1 ? 's' : ''} found. Your email deliverability is significantly impacted and requires immediate attention.`,
    error: 'Could not complete blacklist scan.',
  };

  let summary = summaries[status];
  if (listedOn.length === 0 && unverified.length > 0) {
    summary =
      unverified.length >= totalChecks
        ? 'Blocklist queries failed - could not determine blacklist status.'
        : `No listings found on the blocklists we could reach, but ${unverified.length} of ${totalChecks} queries failed and could not be verified.`;
  }

  return {
    status,
    mxHosts,
    mxIPs,
    listedOn,
    checkedLists: DNSBL_LISTS.map((l) => ({ name: l.name, description: l.description })),
    issues,
    summary,
    onlyPBL,
    unverified,
  };
}
