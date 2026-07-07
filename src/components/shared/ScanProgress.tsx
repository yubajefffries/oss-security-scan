export type ScanPhase = 'dns' | 'email' | 'blacklist' | 'headers' | 'dnssec';

interface Props {
  completed: Set<ScanPhase>;
  active: ScanPhase | null;
}

const STEPS: { key: ScanPhase; label: string }[] = [
  { key: 'dns', label: 'DNS Records' },
  { key: 'email', label: 'Email Auth' },
  { key: 'blacklist', label: 'Blacklist Check' },
  { key: 'headers', label: 'Security Headers' },
  { key: 'dnssec', label: 'DNS Security' },
];

export default function ScanProgress({ completed, active }: Props) {
  return (
    <div className="scan-progress" role="status" aria-label="Scan progress">
      {STEPS.map((step) => {
        const isDone = completed.has(step.key);
        const isActive = active === step.key;
        const status = isDone ? 'done' : isActive ? 'active' : 'pending';

        return (
          <div key={step.key} className={`scan-progress__step scan-progress__step--${status}`}>
            <span className="scan-progress__icon" aria-hidden="true">
              {isDone ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : isActive ? (
                <span className="spinner" />
              ) : (
                <span className="scan-progress__dot" />
              )}
            </span>
            <span className="scan-progress__label">{step.label}</span>
          </div>
        );
      })}
    </div>
  );
}
