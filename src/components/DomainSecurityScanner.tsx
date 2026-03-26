import { useState } from 'react';
import { lookupAll, lookupSpf, lookupDmarc, lookupDkim, type DnsRecord, type DnsLookupResult } from '../lib/dns-over-https';
import { DKIM_SELECTORS, computeGrade, computeBestPractices, type EmailAuthResult, type BestPractices } from '../lib/email-auth-grader';
import { checkBlacklists, type BlacklistReport } from '../lib/blacklist-checker';
import DomainInput from './shared/DomainInput';
import CopyButton from './shared/CopyButton';
import ScanProgress, { type ScanPhase } from './shared/ScanProgress';
import SecuritySummary from './sections/SecuritySummary';
import DnsFoundationSection from './sections/DnsFoundationSection';
import EmailAuthSection from './sections/EmailAuthSection';
import BlacklistSection from './sections/BlacklistSection';
import HeadersSection, { type HeadersResult } from './sections/HeadersSection';

interface ScanState {
  domain: string;
  dns: Record<string, DnsLookupResult> | null;
  emailAuth: EmailAuthResult | null;
  bestPractices: BestPractices | null;
  spfRecord: DnsRecord | null;
  dmarcRecord: DnsRecord | null;
  dkimRecord: DnsRecord | null;
  blacklist: BlacklistReport | null;
  headers: HeadersResult | null;
}

function formatAllResultsText(state: ScanState): string {
  let out = `Domain Security Report - ${state.domain}\n${'='.repeat(56)}\n\n`;

  // DNS section
  if (state.dns) {
    out += `--- DNS Records ---\n`;
    for (const [type, { records, error }] of Object.entries(state.dns)) {
      out += `\n${type}:\n`;
      if (error) out += `  Error: ${error}\n`;
      else if (records.length === 0) out += `  No records found\n`;
      else records.forEach((r) => { out += `  ${r.value} (TTL: ${r.ttl})\n`; });
    }
    out += '\n';
  }

  // Email auth section
  if (state.emailAuth) {
    out += `--- Email Authentication (Grade: ${state.emailAuth.grade}) ---\n`;
    out += `${state.emailAuth.summary}\n\n`;
    out += `SPF: ${state.emailAuth.spf.found ? 'Found' : 'Missing'}`;
    if (state.emailAuth.spf.record) out += ` - ${state.emailAuth.spf.record.value}`;
    out += `\n${state.emailAuth.spf.recommendation}\n\n`;
    out += `DMARC: ${state.emailAuth.dmarc.found ? 'Found' : 'Missing'}`;
    if (state.emailAuth.dmarc.record) out += ` - ${state.emailAuth.dmarc.record.value}`;
    out += `\n${state.emailAuth.dmarc.recommendation}\n\n`;
    out += `DKIM: ${state.emailAuth.dkim.found ? `Found (selector: ${state.emailAuth.dkim.selector})` : 'Not found'}`;
    if (state.emailAuth.dkim.record) out += ` - ${state.emailAuth.dkim.record.value}`;
    out += `\n${state.emailAuth.dkim.recommendation}\n\n`;
  }

  // Blacklist section
  if (state.blacklist) {
    out += `--- Blacklist Check (IP: ${state.blacklist.ip}) ---\n`;
    if (state.blacklist.isSharedHosting) out += `Note: Shared hosting/CDN IP detected\n`;
    for (const bl of state.blacklist.results) {
      out += `${bl.name}: ${bl.listed ? 'LISTED' : 'Clean'}`;
      if (bl.note) out += ` (${bl.note})`;
      out += '\n';
    }
    out += '\n';
  }

  // Security Headers section
  if (state.headers) {
    out += `--- Security Headers (${state.headers.score}/${state.headers.maxScore}) ---\n`;
    out += `${state.headers.summary}\n\n`;
    for (const check of state.headers.checks) {
      out += `${check.name}: ${check.found ? 'Present' : 'Missing'}`;
      if (check.found && check.value) out += ` - ${check.value}`;
      out += '\n';
    }
    out += '\n';
  }

  out += `Scanned at ${new Date().toISOString()}\nPowered by DarkHorse IT Security Tools`;
  return out;
}

export default function DomainSecurityScanner() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [completedPhases, setCompletedPhases] = useState<Set<ScanPhase>>(new Set());
  const [activePhase, setActivePhase] = useState<ScanPhase | null>(null);
  const [state, setState] = useState<ScanState | null>(null);

  async function handleScan(domain: string) {
    setLoading(true);
    setError('');
    setState(null);
    setCompletedPhases(new Set());
    setActivePhase('dns');

    const scanState: ScanState = {
      domain,
      dns: null,
      emailAuth: null,
      bestPractices: null,
      spfRecord: null,
      dmarcRecord: null,
      dkimRecord: null,
      blacklist: null,
      headers: null,
    };

    try {
      // Phase 1: DNS Records + Email Auth in parallel
      setActivePhase('dns');
      const [dnsData, spfRecord, dmarcRecord] = await Promise.all([
        lookupAll(domain),
        lookupSpf(domain),
        lookupDmarc(domain),
      ]);

      scanState.dns = dnsData;
      scanState.spfRecord = spfRecord;
      scanState.dmarcRecord = dmarcRecord;
      setCompletedPhases(new Set(['dns']));
      setState({ ...scanState });

      // Phase 2: DKIM probing (sequential through selectors) + grade
      setActivePhase('email');
      let dkimRecord: DnsRecord | null = null;
      let dkimSelector: string | null = null;
      for (const selector of DKIM_SELECTORS) {
        const found = await lookupDkim(domain, selector);
        if (found) {
          dkimRecord = found;
          dkimSelector = selector;
          break;
        }
      }

      const spf = {
        found: !!spfRecord,
        record: spfRecord,
        strict: spfRecord?.value.includes('-all') ?? false,
        recommendation: !spfRecord
          ? 'Add an SPF record to specify which servers can send email for your domain.'
          : spfRecord.value.includes('-all')
            ? 'SPF is configured with strict enforcement (-all). Excellent.'
            : 'SPF uses soft fail (~all). Consider upgrading to -all for stricter enforcement.',
      };

      const dmarcPolicy = dmarcRecord?.value.match(/p=(reject|quarantine|none)/i)?.[1]?.toLowerCase() ?? 'none';
      const dmarc = {
        found: !!dmarcRecord,
        record: dmarcRecord,
        policy: dmarcPolicy,
        recommendation: !dmarcRecord
          ? 'Add a DMARC record. Without it, spoofed emails from your domain go unchecked.'
          : dmarcPolicy === 'reject'
            ? 'DMARC policy is set to reject. Maximum protection against spoofing.'
            : dmarcPolicy === 'quarantine'
              ? 'DMARC policy is quarantine. Good, but consider upgrading to reject.'
              : 'DMARC policy is set to none (monitoring only). Upgrade to quarantine or reject.',
      };

      const dkim = {
        found: !!dkimRecord,
        selector: dkimSelector,
        record: dkimRecord,
        recommendation: !dkimRecord
          ? 'No DKIM record found for common selectors. Configure DKIM signing with your email provider.'
          : `DKIM record found for selector "${dkimSelector}". Email signing is active.`,
      };

      const { grade, summary } = computeGrade(spf, dmarc, dkim);
      const bestPractices = computeBestPractices(spf, dmarc, dkim);

      scanState.dkimRecord = dkimRecord;
      scanState.emailAuth = { grade, spf, dmarc, dkim, summary };
      scanState.bestPractices = bestPractices;
      setCompletedPhases(new Set(['dns', 'email']));
      setState({ ...scanState });

      // Phase 3: Blacklist check (needs IP from DNS A records)
      setActivePhase('blacklist');
      const aRecords = dnsData['A']?.records ?? [];
      if (aRecords.length > 0) {
        const ip = aRecords[0].value;
        const blacklistReport = await checkBlacklists(ip);
        scanState.blacklist = blacklistReport;
      }
      setCompletedPhases(new Set(['dns', 'email', 'blacklist']));
      setState({ ...scanState });

      // Phase 4: Security Headers scan
      setActivePhase('headers');
      try {
        const headersRes = await fetch('https://darkhorseitsecurity-yubajefffries-projects.vercel.app/api/scan/headers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain }),
        });
        if (headersRes.ok) {
          const headersData: HeadersResult = await headersRes.json();
          scanState.headers = headersData;
        }
      } catch {
        // Headers scan is non-fatal; continue without it
      }
      setCompletedPhases(new Set(['dns', 'email', 'blacklist', 'headers']));
      setActivePhase(null);
      setState({ ...scanState });
    } catch {
      setError('Failed to complete security scan. Please try again.');
    } finally {
      setLoading(false);
      setActivePhase(null);
    }
  }

  // Derived values for summary banner
  const dnsHealthy = state?.dns
    ? Object.values(state.dns).some(({ records }) => records.length > 0)
    : false;
  const blacklistClean = state?.blacklist
    ? state.blacklist.results.filter((r) => r.confidence !== 'low').every((r) => !r.listed)
    : null;

  return (
    <div>
      <DomainInput onSubmit={handleScan} loading={loading} placeholder="yourdomain.com" />

      {(loading || completedPhases.size > 0) && (
        <ScanProgress completed={completedPhases} active={activePhase} />
      )}

      {error && <p className="error-msg">{error}</p>}

      {state && (
        <>
          <SecuritySummary
            dnsHealthy={dnsHealthy}
            emailGrade={state.emailAuth?.grade ?? null}
            blacklistClean={blacklistClean}
            headersScore={state.headers ? { score: state.headers.score, maxScore: state.headers.maxScore, status: state.headers.status } : null}
          />

          {state.dns && (
            <DnsFoundationSection
              domain={state.domain}
              data={state.dns}
              spfRecord={state.spfRecord}
              dmarcRecord={state.dmarcRecord}
              dkimRecord={state.dkimRecord}
            />
          )}

          {state.emailAuth && state.bestPractices && (
            <EmailAuthSection
              domain={state.domain}
              result={state.emailAuth}
              bestPractices={state.bestPractices}
            />
          )}

          {state.blacklist && (
            <BlacklistSection report={state.blacklist} />
          )}

          {state.headers && (
            <HeadersSection result={state.headers} />
          )}

          {completedPhases.size === 4 && (
            <>
              <div style={{ marginTop: 'var(--space-6)', textAlign: 'center' }}>
                <CopyButton text={formatAllResultsText(state)} label="Copy All Results" />
              </div>

              <div className="cta-card">
                <h3 className="cta-card__title">Need help improving your score?</h3>
                <p className="cta-card__text">
                  DarkHorse IT can help you configure your email authentication, secure your DNS
                  foundation, and get your domain off blacklists. We work with businesses across
                  Fargo-Moorhead and nationwide.
                </p>
                <a
                  href="https://darkhorseit.com/contact"
                  className="cta-card__link"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Get in Touch →
                </a>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
