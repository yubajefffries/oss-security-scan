import type { EmailAuthResult } from '../../lib/email-auth-grader';
import type { BestPractices } from '../../lib/email-auth-grader';
import BestPracticeBadge from '../shared/BestPracticeBadge';
import InsightCard from '../shared/InsightCard';
import CopyButton from '../shared/CopyButton';

interface Props {
  domain: string;
  result: EmailAuthResult;
  bestPractices: BestPractices;
}

function FixBlock({ label, record }: { label: string; record: string }) {
  return (
    <div className="fix-block">
      <p className="fix-block__label">{label}</p>
      <div className="fix-block__code">
        <code>{record}</code>
        <CopyButton text={record} label="Copy record" />
      </div>
    </div>
  );
}

function getSpfInsight(spf: EmailAuthResult['spf']): string {
  if (!spf.found) {
    return 'We were unable to find an SPF record for this domain. Without SPF, receiving mail servers have no way to verify which sources are authorized to send on your behalf.';
  }
  if (spf.strict) {
    return 'Great job! You have a valid SPF record with strict enforcement (-all), which specifies exactly which servers can send email for your domain.';
  }
  return 'You have a valid SPF record with soft fail (~all). This is a good start, but upgrading to -all provides stronger enforcement once you\'ve confirmed all legitimate sending sources.';
}

function getDmarcInsight(dmarc: EmailAuthResult['dmarc']): string {
  if (!dmarc.found) {
    return 'We were unable to find a DMARC record. As a result, this domain is not protected against abuse and likely does not meet the current Google and Yahoo sender requirements.';
  }
  if (dmarc.policy === 'reject') {
    return 'Your domain has a valid DMARC record and your policy will prevent abuse of your domain by phishers and spammers. Mailbox providers can reliably block unauthorized email.';
  }
  if (dmarc.policy === 'quarantine') {
    return 'Your domain has a valid DMARC record set to quarantine. Suspicious messages will be sent to spam. To fully take advantage of DMARC, consider upgrading to p=reject.';
  }
  return 'Your domain has a valid DMARC record but the policy is set to none (monitoring only). This does not prevent abuse - phishers and spammers can still send email as your domain.';
}

function getDkimInsight(dkim: EmailAuthResult['dkim']): string {
  if (dkim.found) {
    return `We found a valid DKIM record (selector: ${dkim.selector}). This cryptographic signature helps mailbox providers verify your emails haven't been tampered with in transit.`;
  }
  return 'We couldn\'t find any DKIM records for common selectors. Each email sending source (Google Workspace, Microsoft 365, etc.) should have its own DKIM key configured.';
}

export default function EmailAuthSection({ domain, result, bestPractices }: Props) {
  return (
    <section>
      <div className="grade-display">
        <div className={`grade-badge grade-badge--${result.grade}`} aria-label={`Grade: ${result.grade}`}>
          {result.grade}
        </div>
        <div className="grade-info">
          <p className="grade-info__label">Email Authentication Grade</p>
          <p className="grade-info__summary">{result.summary}</p>
          {bestPractices.allMet && <BestPracticeBadge label="All Best Practices Met" />}
        </div>
      </div>

      <div className="results-grid">
        {/* SPF */}
        <div className={`result-card result-card--${result.spf.found ? (result.spf.strict ? 'pass' : 'warn') : 'fail'}`}>
          <div className="result-card__header">
            <h3 className="result-card__title">SPF</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {bestPractices.spfStrict && <BestPracticeBadge />}
              <span className={`status-badge status-badge--${result.spf.found ? 'pass' : 'fail'}`}>
                {result.spf.found ? 'Found' : 'Missing'}
              </span>
            </div>
          </div>
          {result.spf.record && (
            <div className="record-item">{result.spf.record.value}</div>
          )}

          <InsightCard type={result.spf.found ? 'info' : 'danger'} title="Why This Matters">
            {getSpfInsight(result.spf)}
          </InsightCard>

          {result.spf.found ? (
            <p className="recommendation">{result.spf.recommendation}</p>
          ) : (
            <FixBlock
              label="Add this TXT record to your DNS:"
              record={`v=spf1 include:_spf.google.com ~all`}
            />
          )}

          <details className="explainer">
            <summary>Technical details</summary>
            <div className="explainer__body">
              SPF (Sender Policy Framework) publishes a list of authorized sending IPs in a TXT record.
              Receiving servers check the connecting IP against this list. <code>-all</code> means hard fail
              (reject unauthorized), <code>~all</code> means soft fail (mark but deliver).
              Best practice is <code>-all</code> once you've confirmed all legitimate senders.
            </div>
          </details>
        </div>

        {/* DMARC */}
        <div className={`result-card result-card--${result.dmarc.found ? (result.dmarc.policy === 'reject' ? 'pass' : 'warn') : 'fail'}`}>
          <div className="result-card__header">
            <h3 className="result-card__title">DMARC</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {bestPractices.dmarcReject && <BestPracticeBadge />}
              <span className={`status-badge status-badge--${result.dmarc.found ? (result.dmarc.policy !== 'none' ? 'pass' : 'warn') : 'fail'}`}>
                {result.dmarc.found ? `Policy: ${result.dmarc.policy}` : 'Missing'}
              </span>
            </div>
          </div>
          {result.dmarc.record && (
            <div className="record-item">{result.dmarc.record.value}</div>
          )}

          <InsightCard type={result.dmarc.found ? 'info' : 'danger'} title="Why This Matters">
            {getDmarcInsight(result.dmarc)}
          </InsightCard>

          {result.dmarc.found ? (
            <p className="recommendation">{result.dmarc.recommendation}</p>
          ) : (
            <FixBlock
              label="Add this TXT record at _dmarc.yourdomain.com:"
              record={`v=DMARC1; p=reject; rua=mailto:dmarc-reports@${domain}; pct=100`}
            />
          )}

          <details className="explainer">
            <summary>Technical details</summary>
            <div className="explainer__body">
              DMARC tells receiving servers what to do when SPF or DKIM checks fail.
              <code>p=none</code> monitors only, <code>p=quarantine</code> sends to spam,
              <code>p=reject</code> blocks delivery entirely. Start with <code>p=none</code> and
              monitor reports, then graduate to <code>p=reject</code>. The <code>rua</code> tag
              specifies where aggregate reports are sent.
            </div>
          </details>
        </div>

        {/* DKIM */}
        <div className={`result-card result-card--${result.dkim.found ? 'pass' : 'fail'}`}>
          <div className="result-card__header">
            <h3 className="result-card__title">DKIM</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {bestPractices.dkimFound && <BestPracticeBadge label="Verified" />}
              <span className={`status-badge status-badge--${result.dkim.found ? 'pass' : 'fail'}`}>
                {result.dkim.found ? `Selector: ${result.dkim.selector}` : 'Not found'}
              </span>
            </div>
          </div>
          {result.dkim.record && (
            <div className="record-item" style={{ maxHeight: '80px', overflow: 'auto' }}>
              {result.dkim.record.value}
            </div>
          )}

          <InsightCard type={result.dkim.found ? 'info' : 'danger'} title="Why This Matters">
            {getDkimInsight(result.dkim)}
          </InsightCard>

          <p className="recommendation">{result.dkim.recommendation}</p>

          <details className="explainer">
            <summary>Technical details</summary>
            <div className="explainer__body">
              DKIM (DomainKeys Identified Mail) signs outgoing messages with a private key.
              The public key is published in DNS as a TXT record at
              <code>selector._domainkey.domain</code>. We check common selectors (google, default,
              selector1, selector2, etc.) but your provider may use a custom one.
            </div>
          </details>
        </div>
      </div>
    </section>
  );
}
