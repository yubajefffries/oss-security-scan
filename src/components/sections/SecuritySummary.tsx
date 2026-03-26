import type { Grade } from '../../lib/email-auth-grader';

interface Props {
  dnsHealthy: boolean;
  emailGrade: Grade | null;
  blacklistClean: boolean | null;
  headersScore: { score: number; maxScore: number; status: string } | null;
}

export default function SecuritySummary({ dnsHealthy, emailGrade, blacklistClean, headersScore }: Props) {
  return (
    <div className="security-summary">
      <div className="security-summary__item">
        <span className={`security-summary__indicator security-summary__indicator--${dnsHealthy ? 'pass' : 'warn'}`} aria-hidden="true">
          {dnsHealthy ? '✓' : '!'}
        </span>
        <div>
          <p className="security-summary__label">DNS Health</p>
          <p className="security-summary__value">{dnsHealthy ? 'Records Found' : 'Issues Detected'}</p>
        </div>
      </div>

      <div className="security-summary__item">
        <span className={`security-summary__indicator security-summary__indicator--${
          emailGrade === null ? 'pending' : emailGrade <= 'B' ? 'pass' : emailGrade <= 'C' ? 'warn' : 'fail'
        }`} aria-hidden="true">
          {emailGrade ?? '-'}
        </span>
        <div>
          <p className="security-summary__label">Email Auth</p>
          <p className="security-summary__value">{emailGrade ? `Grade ${emailGrade}` : 'Checking...'}</p>
        </div>
      </div>

      <div className="security-summary__item">
        <span className={`security-summary__indicator security-summary__indicator--${
          blacklistClean === null ? 'pending' : blacklistClean ? 'pass' : 'fail'
        }`} aria-hidden="true">
          {blacklistClean === null ? '...' : blacklistClean ? '✓' : '!'}
        </span>
        <div>
          <p className="security-summary__label">Blacklist Status</p>
          <p className="security-summary__value">
            {blacklistClean === null ? 'Checking...' : blacklistClean ? 'All Clear' : 'Listed'}
          </p>
        </div>
      </div>

      <div className="security-summary__item">
        <span className={`security-summary__indicator security-summary__indicator--${
          headersScore === null ? 'pending' : headersScore.status === 'pass' ? 'pass' : headersScore.status === 'warning' ? 'warn' : 'fail'
        }`} aria-hidden="true">
          {headersScore === null ? '...' : `${headersScore.score}/${headersScore.maxScore}`}
        </span>
        <div>
          <p className="security-summary__label">Security Headers</p>
          <p className="security-summary__value">
            {headersScore === null
              ? 'Checking...'
              : headersScore.status === 'pass'
                ? 'All Present'
                : `${headersScore.score}/${headersScore.maxScore} Found`}
          </p>
        </div>
      </div>
    </div>
  );
}
