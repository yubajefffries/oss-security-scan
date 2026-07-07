// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import dns from 'dns/promises';

export type ScanStatus = 'pass' | 'warning' | 'critical' | 'error';

export interface SpfResult {
  found: boolean;
  record?: string;
  policy?: 'hardfail' | 'softfail' | 'neutral' | 'all' | 'dangerous';
  lookupCount?: number;
  issues: string[];
}

export interface DmarcResult {
  found: boolean;
  record?: string;
  policy?: 'none' | 'quarantine' | 'reject';
  hasReporting: boolean;
  issues: string[];
}

export interface DkimSelectorResult {
  selector: string;
  found: boolean;
}

export interface EmailAuthResult {
  status: ScanStatus;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: {
    selectorsChecked: DkimSelectorResult[];
    anyFound: boolean;
  };
  summary: string;
}

const DKIM_SELECTORS = [
  'google', 'default', 'selector1', 'selector2',
  'k1', 'mail', 'dkim', 'email', 'mx',
  's1', 's2', 'protonmail', 'mailchimp',
];

/**
 * Joins the 255-character TXT chunks of each record before matching.
 * A naive .flat() treats each chunk as its own record, truncating any
 * SPF/DMARC record longer than 255 characters.
 */
function joinTxtChunks(records: string[][]): string[] {
  return records.map((chunks) => chunks.join(''));
}

/**
 * Counts DNS-querying terms per RFC 7208 section 4.6.4: the include, a, mx,
 * ptr, and exists mechanisms (bare or with arguments, any qualifier) plus
 * the redirect= modifier. The previous regex only matched "mechanism:"
 * forms, missing bare "a"/"mx" and redirect= entirely.
 */
function countSpfLookups(record: string): number {
  const terms = record.trim().split(/\s+/).slice(1); // skip "v=spf1"
  let count = 0;
  for (const rawTerm of terms) {
    const term = rawTerm.toLowerCase().replace(/^[+\-~?]/, '');
    if (/^(include|exists):/.test(term)) count++;
    else if (/^(a|mx|ptr)(:|\/|$)/.test(term)) count++;
    else if (/^redirect=/.test(term)) count++;
  }
  return count;
}

async function checkSpf(domain: string): Promise<SpfResult> {
  try {
    const records = await dns.resolveTxt(domain);
    const spfRecord = joinTxtChunks(records)
      .find((r) => r.toLowerCase().startsWith('v=spf1'));

    if (!spfRecord) {
      return {
        found: false,
        issues: ['No SPF record found. Attackers can send emails impersonating your domain.'],
      };
    }

    const issues: string[] = [];
    let policy: SpfResult['policy'];

    // Locate the "all" mechanism as a standalone term (case-insensitive).
    // Substring checks like record.includes('-all') missed uppercase variants
    // and, worse, graded a bare "all" (implicit "+all", i.e. anyone may send)
    // as a safe softfail default.
    const terms = spfRecord.trim().split(/\s+/).slice(1).map((t) => t.toLowerCase());
    const allTerm = terms.find((t) => /^[+\-~?]?all$/.test(t));
    const hasRedirect = terms.some((t) => t.startsWith('redirect='));

    if (allTerm === '+all' || allTerm === 'all') {
      policy = 'dangerous';
      issues.push(
        allTerm === 'all'
          ? 'SPF ends with a bare "all" (implicit "+all") - this allows anyone to send email as your domain. Use "-all" instead.'
          : 'SPF uses "+all" - this allows anyone to send email as your domain.'
      );
    } else if (allTerm === '-all') {
      policy = 'hardfail';
    } else if (allTerm === '~all') {
      policy = 'softfail';
      issues.push('SPF uses "~all" (softfail) - unauthorized emails may still be delivered. Consider "-all" for strict enforcement.');
    } else if (allTerm === '?all') {
      policy = 'neutral';
      issues.push('SPF uses "?all" (neutral) - provides no protection against spoofing.');
    } else if (!hasRedirect) {
      // redirect= legitimately replaces "all" (RFC 7208 section 6.1), so only
      // flag a missing "all" when there is no redirect modifier either.
      issues.push('SPF record is missing an "all" mechanism - incomplete protection.');
    }

    const lookupCount = countSpfLookups(spfRecord);
    if (lookupCount > 10) {
      issues.push(`SPF record has ${lookupCount} DNS lookups (max is 10) - emails may be rejected.`);
    }

    return { found: true, record: spfRecord, policy, lookupCount, issues };
  } catch {
    return { found: false, issues: ['Could not retrieve SPF record (DNS lookup failed).'] };
  }
}

async function checkDmarc(domain: string): Promise<DmarcResult> {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = joinTxtChunks(records)
      .find((r) => r.toLowerCase().startsWith('v=dmarc1'));

    if (!dmarcRecord) {
      return {
        found: false,
        hasReporting: false,
        issues: ['No DMARC record found. Without DMARC, email spoofing attacks are significantly more effective.'],
      };
    }

    const issues: string[] = [];
    const policyMatch = dmarcRecord.match(/p=([a-z]+)/i);
    const policy = (policyMatch?.[1]?.toLowerCase() ?? 'none') as DmarcResult['policy'];
    const hasReporting = dmarcRecord.includes('rua=') || dmarcRecord.includes('ruf=');

    if (policy === 'none') {
      issues.push('DMARC policy is "none" - monitoring only, no protection. Upgrade to "quarantine" or "reject".');
    } else if (policy === 'quarantine') {
      issues.push('DMARC policy is "quarantine" - spoofed emails go to spam. Consider upgrading to "reject" for full protection.');
    }

    if (!hasReporting) {
      issues.push('No DMARC reporting address (rua=) configured - you won\'t receive alerts about spoofing attempts.');
    }

    return { found: true, record: dmarcRecord, policy, hasReporting, issues };
  } catch {
    return {
      found: false,
      hasReporting: false,
      issues: ['No DMARC record found. Without DMARC, email spoofing attacks are significantly more effective.'],
    };
  }
}

async function checkDkim(domain: string): Promise<{ selectorsChecked: DkimSelectorResult[]; anyFound: boolean }> {
  const results = await Promise.allSettled(
    DKIM_SELECTORS.map(async (selector) => {
      try {
        const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
        // Require an actual DKIM key record. Any stray TXT at the selector
        // (e.g. a wildcard TXT record) must not count as "DKIM found".
        const found = joinTxtChunks(records).some(
          (r) => /v=dkim1/i.test(r) || /(^|;)\s*p\s*=/i.test(r)
        );
        return { selector, found };
      } catch {
        return { selector, found: false };
      }
    })
  );

  const selectorsChecked = results.map((r) =>
    r.status === 'fulfilled' ? r.value : { selector: 'unknown', found: false }
  );

  return {
    selectorsChecked,
    anyFound: selectorsChecked.some((s) => s.found),
  };
}

function computeStatus(spf: SpfResult, dmarc: DmarcResult, dkimAnyFound: boolean): ScanStatus {
  // Critical: both SPF and DMARC missing, dangerous SPF, or DMARC set to none (monitoring only)
  const critical =
    (!spf.found && !dmarc.found) ||
    spf.policy === 'dangerous' ||
    (!dmarc.found && spf.policy !== 'hardfail') ||
    dmarc.policy === 'none';

  if (critical) return 'critical';

  // Warning: any individual weakness (DKIM not found is warning since selector detection is limited)
  const warning =
    !spf.found ||
    !dkimAnyFound ||
    spf.policy === 'softfail' ||
    spf.policy === 'neutral' ||
    dmarc.policy === 'quarantine' ||
    !dmarc.hasReporting ||
    spf.issues.length > 0 ||
    dmarc.issues.length > 0;

  return warning ? 'warning' : 'pass';
}

export async function scanEmailAuth(domain: string): Promise<EmailAuthResult> {
  const [spf, dmarc, dkim] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
    checkDkim(domain),
  ]);

  const status = computeStatus(spf, dmarc, dkim.anyFound);

  const summaries: Record<ScanStatus, string> = {
    critical: 'Your domain has critical email authentication gaps. Attackers can impersonate your business in emails.',
    warning: 'Email authentication is partially configured. Some spoofing risks remain.',
    pass: 'Email authentication is properly configured. Your domain is protected against spoofing.',
    error: 'Could not complete email authentication scan.',
  };

  return { status, spf, dmarc, dkim, summary: summaries[status] };
}