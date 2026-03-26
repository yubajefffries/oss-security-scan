import type { DnsRecord, DnsLookupResult } from '../../lib/dns-over-https';
import BestPracticeBadge from '../shared/BestPracticeBadge';
import InsightCard from '../shared/InsightCard';

interface Props {
  domain: string;
  data: Record<string, DnsLookupResult>;
  spfRecord: DnsRecord | null;
  dmarcRecord: DnsRecord | null;
  dkimRecord: DnsRecord | null;
}

const TYPE_LABELS: Record<string, { label: string; icon: string; description: string }> = {
  A: {
    label: 'A Records (IPv4)',
    icon: '\u{1F310}',
    description: 'These point your domain to the IP address where your website is hosted. Without an A record, nobody can reach your site.',
  },
  AAAA: {
    label: 'AAAA Records (IPv6)',
    icon: '\u{1F310}',
    description: 'IPv6 addresses for your domain. Most domains only use IPv4 (A records) today.',
  },
  MX: {
    label: 'MX Records (Mail)',
    icon: '\u{1F4E7}',
    description: 'Mail exchange servers that handle email for your domain. Without MX records, your domain can\'t receive email.',
  },
  TXT: {
    label: 'TXT Records',
    icon: '\u{1F4DD}',
    description: 'Text records used for verification and email security. SPF, DMARC, and DKIM records are stored here.',
  },
  NS: {
    label: 'NS Records (Nameservers)',
    icon: '\u{1F3F7}\u{FE0F}',
    description: 'The nameservers that control your domain\'s DNS. These are set by your domain registrar.',
  },
};

function isSecurityRecord(value: string): boolean {
  return value.startsWith('v=spf1') || value.startsWith('v=DMARC1') || value.includes('v=DKIM1');
}

export default function DnsFoundationSection({ domain, data, spfRecord, dmarcRecord, dkimRecord }: Props) {
  const securityRecordCount = [spfRecord, dmarcRecord, dkimRecord].filter(Boolean).length;

  return (
    <section>
      <div className="foundation-callout">
        <h2 className="foundation-callout__title">DNS is Your Foundation</h2>
        <p className="foundation-callout__text">
          If your DNS isn't set up correctly, everything else is built on an unstable foundation.
          Think of it as the foundation of a house - email delivery, website availability, and
          security all depend on these records being correct.
        </p>
        {securityRecordCount === 3 && (
          <BestPracticeBadge label="All Security Records Present" />
        )}
      </div>

      <InsightCard type="info" title="What you're looking at">
        These are the DNS records published for <strong>{domain}</strong>. SPF, DMARC, and DKIM
        records are highlighted - they control who can send email as your domain.
      </InsightCard>

      <div className="results-grid" style={{ marginTop: 'var(--space-4)' }}>
        {Object.entries(data).map(([type, { records, error: typeError }]) => {
          const meta = TYPE_LABELS[type];
          const hasRecords = records.length > 0;

          // AAAA with no records is informational, not a warning
          const status = typeError
            ? 'fail'
            : hasRecords
              ? 'pass'
              : type === 'AAAA'
                ? 'info'
                : 'warn';

          return (
            <div key={type} className={`result-card result-card--${status}`}>
              <div className="result-card__header">
                <h3 className="result-card__title">
                  <span aria-hidden="true">{meta?.icon} </span>
                  {meta?.label ?? type}
                </h3>
                <span className={`status-badge status-badge--${status}`}>
                  {typeError ? 'Error' : hasRecords ? `${records.length} found` : 'None'}
                </span>
              </div>

              {meta?.description && (
                <p style={{ color: 'var(--dh-muted)', fontSize: '0.82rem', lineHeight: '1.5', marginBottom: 'var(--space-3)' }}>
                  {meta.description}
                </p>
              )}

              {typeError && <p className="error-msg">{typeError}</p>}

              {hasRecords && (
                <ul className="record-list">
                  {records.map((r, i) => (
                    <li
                      key={i}
                      className={`record-item${isSecurityRecord(r.value) ? ' record-item--highlight' : ''}`}
                    >
                      {r.value}
                      <span style={{ color: 'var(--dh-muted)', marginLeft: '8px', fontSize: '0.7rem' }}>
                        TTL {r.ttl}
                      </span>
                    </li>
                  ))}
                </ul>
              )}

              {!hasRecords && !typeError && (
                <p style={{ color: 'var(--dh-muted)', fontSize: '0.85rem', lineHeight: '1.6' }}>
                  {type === 'AAAA'
                    ? 'No IPv6 address configured. This is common - most domains only use IPv4 (A records) today. IPv6 adoption is growing but not required. Your site works fine without it.'
                    : `No ${type} records found for this domain.`}
                </p>
              )}

              {type === 'NS' && hasRecords && (
                <InsightCard type="warning" title="Secure your domain registrar account">
                  Your domain registrar account (where your nameservers are managed) must be secured
                  with a strong, unique, random password and multi-factor authentication. Use a
                  time-based one-time password (TOTP) app like Microsoft Authenticator, or a hardware
                  security key or passkey. This is critical - if someone compromises your registrar
                  account, they control your entire domain, email, and website.
                </InsightCard>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
