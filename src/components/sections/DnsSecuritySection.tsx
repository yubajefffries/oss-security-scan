import type { DnsSecurityReport } from '../../lib/dns-security-checker';
import BestPracticeBadge from '../shared/BestPracticeBadge';
import InsightCard from '../shared/InsightCard';

interface Props {
  domain: string;
  report: DnsSecurityReport;
}

type CardStatus = 'pass' | 'warn' | 'info' | 'fail';

interface CheckCard {
  key: string;
  title: string;
  icon: string;
  status: CardStatus;
  badge: string;
  description: string;
  records: string[];
  detail: string;
}

function buildCards(report: DnsSecurityReport): CheckCard[] {
  const { dnssec, caa, bimi, mtaSts } = report;

  const dnssecCard: CheckCard = {
    key: 'dnssec',
    title: 'DNSSEC',
    icon: '\u{1F510}',
    status: dnssec.error ? 'fail' : dnssec.validated ? 'pass' : 'warn',
    badge: dnssec.error ? 'Error' : dnssec.validated ? 'Validated' : dnssec.dsFound ? 'Not validating' : 'Not enabled',
    description: 'Cryptographically signs your DNS records so resolvers can detect forged responses (cache poisoning).',
    records: [],
    detail: dnssec.error
      ? 'DNSSEC status could not be determined (lookup failed).'
      : dnssec.validated
        ? 'A DS record exists at the parent zone and the chain validates. Resolvers can verify your DNS responses are authentic.'
        : dnssec.dsFound
          ? 'A DS record exists but the chain did not validate - broken signatures can make your domain unresolvable for validating resolvers. Check your DNSSEC configuration.'
          : 'DNSSEC is not enabled. DNS responses for your domain can be forged. Most registrars and DNS hosts can enable it with a few clicks.',
  };

  const caaCard: CheckCard = {
    key: 'caa',
    title: 'CAA Records',
    icon: '\u{1F4DC}',
    status: caa.error ? 'fail' : caa.found ? 'pass' : 'warn',
    badge: caa.error ? 'Error' : caa.found ? `${caa.records.length} found` : 'None',
    description: 'Restricts which certificate authorities are allowed to issue SSL/TLS certificates for your domain.',
    records: caa.records,
    detail: caa.error
      ? 'CAA lookup failed - could not determine your certificate issuance policy.'
      : caa.found
        ? 'Certificate issuance is restricted to the authorities you approve.'
        : 'Without a CAA record, any certificate authority in the world can issue certificates for your domain. Add one that names only the CAs you actually use (e.g. letsencrypt.org).',
  };

  const bimiCard: CheckCard = {
    key: 'bimi',
    title: 'BIMI',
    icon: '\u{1F3F5}\u{FE0F}',
    status: bimi.found ? 'pass' : 'info',
    badge: bimi.found ? 'Configured' : 'Not configured',
    description: 'Displays your brand logo next to authenticated email in supporting inboxes (Gmail, Apple Mail, Yahoo).',
    records: bimi.record ? [bimi.record.value] : [],
    detail: bimi.found
      ? 'A BIMI record is published. Supporting inboxes can show your logo on authenticated mail.'
      : 'Optional branding feature - not a security control. Requires DMARC at enforcement (quarantine or reject) plus a published SVG logo.',
  };

  const policy = mtaSts.policy;
  const mtaStsCard: CheckCard = {
    key: 'mta-sts',
    title: 'MTA-STS',
    icon: '\u{2709}\u{FE0F}',
    status: !mtaSts.txtFound
      ? 'warn'
      : policy === undefined
        ? 'info'
        : policy.fetched && policy.mode === 'enforce' && policy.issues.length === 0
          ? 'pass'
          : 'warn',
    badge: !mtaSts.txtFound
      ? 'None'
      : policy === undefined
        ? 'Record found'
        : policy.fetched
          ? `Mode: ${policy.mode ?? 'unknown'}`
          : 'Policy unreachable',
    description: 'Tells sending mail servers to require encrypted (TLS) connections to your mail servers, blocking downgrade attacks.',
    records: mtaSts.record ? [mtaSts.record.value] : [],
    detail: !mtaSts.txtFound
      ? 'No MTA-STS record found. An active attacker can downgrade inbound mail connections to unencrypted SMTP. Google Workspace and Microsoft 365 both support MTA-STS.'
      : policy === undefined
        ? 'The MTA-STS record is published. The policy file could not be verified in this scan (server check unavailable).'
        : policy.fetched
          ? policy.issues.length === 0
            ? 'The MTA-STS record and policy file are valid and in enforce mode. Inbound mail transport is protected.'
            : policy.issues.join(' ')
          : policy.issues.join(' ') || 'The policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt could not be fetched - senders will ignore the policy.',
  };

  return [dnssecCard, caaCard, bimiCard, mtaStsCard];
}

export default function DnsSecuritySection({ domain, report }: Props) {
  const cards = buildCards(report);
  const securityCards = cards.filter((c) => c.key !== 'bimi');
  const allPass = securityCards.every((c) => c.status === 'pass');

  return (
    <section>
      <h2 style={{ fontSize: '1.1rem', marginBottom: 'var(--space-4)' }}>
        DNS Security
      </h2>

      <InsightCard type="info" title="What is DNS security?">
        These checks go beyond basic records: DNSSEC proves your DNS answers haven't been tampered
        with, CAA controls who may issue certificates for <strong>{domain}</strong>, and MTA-STS
        keeps email delivered to you encrypted in transit. BIMI is an optional branding bonus that
        rewards strong email authentication.
      </InsightCard>

      {allPass && <BestPracticeBadge label="DNS Security Configured" />}

      <div className="results-grid" style={{ marginTop: 'var(--space-4)' }}>
        {cards.map((card) => (
          <div key={card.key} className={`result-card result-card--${card.status}`}>
            <div className="result-card__header">
              <h3 className="result-card__title">
                <span aria-hidden="true">{card.icon} </span>
                {card.title}
              </h3>
              <span className={`status-badge status-badge--${card.status}`}>
                {card.badge}
              </span>
            </div>

            <p style={{ color: 'var(--dh-muted)', fontSize: '0.82rem', lineHeight: '1.5', marginBottom: 'var(--space-3)' }}>
              {card.description}
            </p>

            {card.records.length > 0 && (
              <ul className="record-list">
                {card.records.map((value, i) => (
                  <li key={i} className="record-item">{value}</li>
                ))}
              </ul>
            )}

            <p style={{ color: 'var(--dh-text)', fontSize: '0.85rem', lineHeight: '1.6', marginTop: card.records.length > 0 ? 'var(--space-3)' : 0 }}>
              {card.detail}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
