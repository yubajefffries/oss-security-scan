import { useState } from 'react';
import type { BlacklistReport } from '../../lib/blacklist-checker';
import InsightCard from '../shared/InsightCard';

interface Props {
  report: BlacklistReport;
}

export default function BlacklistSection({ report }: Props) {
  const [showLowConfidence, setShowLowConfidence] = useState(false);
  const [showPrevention, setShowPrevention] = useState(false);

  const highConfidence = report.results.filter((r) => r.confidence !== 'low');
  const lowConfidence = report.results.filter((r) => r.confidence === 'low');
  const listedCount = report.results.filter((r) => r.listed && r.confidence !== 'low').length;

  return (
    <section>
      <h2 style={{ fontSize: '1.1rem', marginBottom: 'var(--space-4)' }}>
        Blacklist Check
        <span style={{ fontWeight: 400, fontSize: '0.85rem', color: 'var(--dh-muted)', marginLeft: '8px' }}>
          IP: {report.ip}
        </span>
      </h2>

      <InsightCard type="info" title="What is a blacklist check?">
        Email blacklists are databases maintained by security organizations that track IP addresses
        known to send spam or malicious email. We check your domain's IP against 6 major blacklists.
        Being listed doesn't always mean you did something wrong - shared hosting, a compromised
        account, or even a misconfigured server can land you on a list. Most blacklists have a
        straightforward removal process.
      </InsightCard>

      {report.isSharedHosting && report.sharedHostingNote && (
        <InsightCard type="warning" title="Shared Hosting Detected">
          {report.sharedHostingNote}
        </InsightCard>
      )}

      {listedCount > 0 ? (
        <InsightCard type="warning" title={`Listed on ${listedCount} blacklist${listedCount > 1 ? 's' : ''}`}>
          Your IP appears on {listedCount} blacklist{listedCount > 1 ? 's' : ''}. This is more
          common than you might think, especially on shared hosting. Here's what to do:
          <ol style={{ margin: 'var(--space-2) 0 0', paddingLeft: '1.2em', fontSize: '0.85rem', lineHeight: '1.7' }}>
            <li>Check if you're on shared hosting (the IP may be listed due to another tenant).</li>
            <li>Contact the blacklist's removal page - most have a self-service delisting process.</li>
            <li>Investigate the root cause: compromised email accounts, open mail relays, or misconfigured servers are the usual culprits.</li>
          </ol>
        </InsightCard>
      ) : (
        <InsightCard type="success" title="All Clear">
          Your IP is not listed on any major blacklists. Good standing with email providers.
        </InsightCard>
      )}

      <div className="blacklist-grid">
        {highConfidence.map((bl) => (
          <div key={bl.host} className={`blacklist-item blacklist-item--${bl.listed ? 'listed' : 'clean'}`}>
            <span className="blacklist-item__icon" aria-hidden="true">
              {bl.listed ? '\u26A0' : '\u2713'}
            </span>
            <div className="blacklist-item__info">
              <p className="blacklist-item__name">
                <a href={bl.removalUrl} target="_blank" rel="noopener noreferrer" className="blacklist-item__link">
                  {bl.name}
                </a>
              </p>
              <p className="blacklist-item__desc">{bl.description}</p>
              {bl.listed && bl.note && (
                <p className="blacklist-item__note">{bl.note}</p>
              )}
            </div>
            <span className={`status-badge status-badge--${bl.listed ? 'fail' : 'pass'}`}>
              {bl.listed ? 'Listed' : 'Clean'}
            </span>
          </div>
        ))}
      </div>

      <details
        className="explainer"
        style={{ marginTop: 'var(--space-4)' }}
        open={showPrevention}
        onToggle={(e) => setShowPrevention((e.target as HTMLDetailsElement).open)}
      >
        <summary>How to prevent future listings</summary>
        <div className="explainer__body">
          <ul style={{ margin: 0, paddingLeft: '1.2em', lineHeight: '1.8' }}>
            <li>Keep your email authentication (SPF, DKIM, DMARC) properly configured</li>
            <li>Monitor email sending accounts for compromised credentials</li>
            <li>Use dedicated IPs for email sending when possible</li>
            <li>Regularly review your email sending logs for unusual activity</li>
          </ul>
        </div>
      </details>

      {lowConfidence.length > 0 && (
        <div style={{ marginTop: 'var(--space-4)' }}>
          <button
            type="button"
            className="copy-btn"
            onClick={() => setShowLowConfidence(!showLowConfidence)}
            style={{ fontSize: '0.8rem' }}
          >
            {showLowConfidence ? 'Hide' : 'Show'} low-confidence results ({lowConfidence.length})
          </button>

          {showLowConfidence && (
            <div className="blacklist-grid" style={{ marginTop: 'var(--space-3)' }}>
              {lowConfidence.map((bl) => (
                <div key={bl.host} className={`blacklist-item blacklist-item--${bl.listed ? 'listed' : 'clean'} blacklist-item--low`}>
                  <span className="blacklist-item__icon" aria-hidden="true">
                    {bl.listed ? '?' : '\u2713'}
                  </span>
                  <div className="blacklist-item__info">
                    <p className="blacklist-item__name">
                <a href={bl.removalUrl} target="_blank" rel="noopener noreferrer" className="blacklist-item__link">
                  {bl.name}
                </a>
              </p>
                    <p className="blacklist-item__desc">{bl.description}</p>
                    {bl.note && <p className="blacklist-item__note">{bl.note}</p>}
                  </div>
                  <span className={`status-badge status-badge--${bl.listed ? 'warn' : 'pass'}`}>
                    {bl.listed ? 'Low confidence' : 'Clean'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
