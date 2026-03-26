import { useState } from 'react';
import BestPracticeBadge from '../shared/BestPracticeBadge';
import CopyButton from '../shared/CopyButton';

export interface HeaderCheck {
  name: string;
  key: string;
  found: boolean;
  value: string | null;
  description: string;
  impact: string;
  fix: string;
}

export interface HeadersResult {
  score: number;
  maxScore: number;
  checks: HeaderCheck[];
  status: 'pass' | 'warning' | 'critical';
  summary: string;
}

interface Props {
  result: HeadersResult;
}

const EXPLANATIONS: Record<
  string,
  { what: string; risk: string; why: string; fixLabel: string; present: string }
> = {
  'strict-transport-security': {
    what: 'Forces browsers to always use HTTPS. Once set, the browser will refuse to connect over plain HTTP for the duration specified.',
    risk: 'SSL stripping — an attacker on the same network can downgrade your visitors\u2019 connections to unencrypted HTTP, intercepting everything they send including passwords and payment details.',
    why: 'Any site handling logins or customer data needs this header. It\u2019s the simplest way to guarantee encrypted connections.',
    fixLabel: 'Add this header to your server response:',
    present: 'HSTS is active. Browsers will enforce HTTPS connections to your site.',
  },
  'content-security-policy': {
    what: 'Controls which scripts, styles, images, and other resources are allowed to load on your pages. Acts as an allowlist for content sources.',
    risk: 'XSS (cross-site scripting) — attackers inject malicious scripts that steal customer data, hijack sessions, or redirect users to phishing sites.',
    why: 'XSS is one of the most common web attacks. CSP is the strongest browser-side defense against it.',
    fixLabel: 'Add this header (adjust sources to match your site):',
    present: 'CSP is active. Your site has a policy controlling which resources can load.',
  },
  'x-frame-options': {
    what: 'Prevents your site from being embedded in hidden iframes on other websites.',
    risk: 'Clickjacking — users are tricked into clicking invisible buttons overlaid on your site. They think they\u2019re clicking something harmless but are actually performing actions on your site.',
    why: 'Could let attackers steal credentials or make unauthorized purchases on behalf of your users.',
    fixLabel: 'Add this header to your server response:',
    present: 'X-Frame-Options is set. Your site cannot be embedded in frames on other domains.',
  },
  'x-content-type-options': {
    what: 'Stops browsers from guessing (MIME sniffing) the type of a file. The browser will strictly use the Content-Type you declare.',
    risk: 'MIME sniffing — attackers upload a file that looks like an image but is actually a script. Without this header, the browser may execute it.',
    why: 'Any site with file uploads is vulnerable. This single header eliminates an entire class of attacks.',
    fixLabel: 'Add this header to your server response:',
    present: 'MIME sniffing protection is active. Browsers will respect your declared content types.',
  },
  'referrer-policy': {
    what: 'Controls how much URL information your site shares with other sites when a user clicks an outgoing link.',
    risk: 'Referrer leakage — sensitive data in your URLs (account IDs, tokens, search queries) can be sent to third-party sites you link to.',
    why: 'Account pages, password reset links, and session tokens could leak through the Referer header without a policy in place.',
    fixLabel: 'Add this header to your server response:',
    present: 'Referrer policy is configured. Your URLs are protected when users navigate away.',
  },
  'permissions-policy': {
    what: 'Controls which browser features (camera, microphone, location, payment) your site and any embedded third-party scripts can access.',
    risk: 'Third-party scripts (ads, analytics, widgets) could silently access device features like the camera or microphone without the user realizing.',
    why: 'Blocking unused browser features costs nothing and prevents embedded scripts from exploiting them. It\u2019s a free security win.',
    fixLabel: 'Add this header to your server response:',
    present: 'Permissions policy is active. Browser features are restricted to your declared policy.',
  },
};

function HeaderRow({ check }: { check: HeaderCheck }) {
  const [expanded, setExpanded] = useState(false);
  const explanation = EXPLANATIONS[check.key];

  return (
    <div className={`header-check header-check--${check.found ? 'pass' : 'fail'}`}>
      <div className="header-check__row" onClick={() => setExpanded(!expanded)} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); } }}>
        <span className="header-check__icon" aria-hidden="true">
          {check.found ? (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12" />
            </svg>
          ) : (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          )}
        </span>
        <div className="header-check__info">
          <p className="header-check__name">{check.name}</p>
          {check.found && check.value && (
            <p className="header-check__value">{check.value}</p>
          )}
        </div>
        <div className="header-check__badges">
          {check.found && <BestPracticeBadge label="Secured" />}
          <span className={`status-badge status-badge--${check.found ? 'pass' : 'fail'}`}>
            {check.found ? 'Present' : 'Missing'}
          </span>
        </div>
        <span className={`header-check__chevron ${expanded ? 'header-check__chevron--open' : ''}`} aria-hidden="true">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </span>
      </div>

      <button
        type="button"
        className="header-check__toggle"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? 'Hide details' : 'What does this mean?'}
      </button>

      {expanded && (
        <div className="header-check__details">
          {check.found ? (
            <div className="header-check__present">
              <p className="header-check__present-text">
                <strong>You're good.</strong> {explanation?.present ?? check.description}
              </p>
            </div>
          ) : (
            explanation && (
              <div className="header-check__missing">
                <div className="header-check__detail-block">
                  <h4 className="header-check__detail-label">What is this?</h4>
                  <p className="header-check__detail-text">{explanation.what}</p>
                </div>
                <div className="header-check__detail-block">
                  <h4 className="header-check__detail-label">What can happen?</h4>
                  <p className="header-check__detail-text">{explanation.risk}</p>
                </div>
                <div className="header-check__detail-block">
                  <h4 className="header-check__detail-label">Why fix this?</h4>
                  <p className="header-check__detail-text">{explanation.why}</p>
                </div>
                <div className="header-check__detail-block">
                  <h4 className="header-check__detail-label">How to fix</h4>
                  <p className="header-check__detail-subtext">{explanation.fixLabel}</p>
                  <div className="fix-block">
                    <div className="fix-block__code">
                      <code>{check.fix}</code>
                      <CopyButton text={check.fix} label="Copy header" />
                    </div>
                  </div>
                </div>
              </div>
            )
          )}
        </div>
      )}
    </div>
  );
}

export default function HeadersSection({ result }: Props) {
  const pct = Math.round((result.score / result.maxScore) * 100);

  return (
    <section>
      <h2 style={{ fontSize: '1.1rem', marginBottom: 'var(--space-4)' }}>
        Security Headers
      </h2>

      <div className="grade-display">
        <div
          className={`grade-badge grade-badge--${result.status === 'pass' ? 'A' : result.status === 'warning' ? 'C' : 'F'}`}
          aria-label={`Score: ${result.score}/${result.maxScore}`}
        >
          {result.score}/{result.maxScore}
        </div>
        <div className="grade-info">
          <p className="grade-info__label">Security Headers Score</p>
          <p className="grade-info__summary">{result.summary}</p>
          {result.status === 'pass' && <BestPracticeBadge label="All Headers Present" />}
        </div>
      </div>

      <div className="headers-progress">
        <div className="headers-progress__bar">
          <div
            className={`headers-progress__fill headers-progress__fill--${result.status}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="headers-progress__label">{result.score} of {result.maxScore} headers present</span>
      </div>

      <div className="headers-list">
        {result.checks.map((check) => (
          <HeaderRow key={check.key} check={check} />
        ))}
      </div>
    </section>
  );
}
