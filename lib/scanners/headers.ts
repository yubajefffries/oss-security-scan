// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

export interface HeaderCheck {
  name: string;
  key: string;
  found: boolean;
  value?: string;
  description: string;
  impact: string;
  fix: string;
}

export interface HeadersResult {
  status: 'pass' | 'warning' | 'critical' | 'error';
  score: number;
  maxScore: number;
  checks: HeaderCheck[];
  issues: string[];
  summary: string;
}

const HEADER_DEFINITIONS: Array<Omit<HeaderCheck, 'found' | 'value'>> = [
  {
    name: 'HSTS',
    key: 'strict-transport-security',
    description: 'Forces browsers to always use HTTPS when visiting your site.',
    impact: 'Without HSTS, visitors could be silently downgraded to unencrypted HTTP by attackers.',
    fix: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  {
    name: 'Content Security Policy',
    key: 'content-security-policy',
    description: 'Controls which resources (scripts, images) browsers can load on your site.',
    impact: 'Without CSP, attackers can inject malicious scripts that steal customer data (XSS attacks).',
    fix: 'Add: Content-Security-Policy: default-src \'self\'; (customize based on your resources)',
  },
  {
    name: 'X-Frame-Options',
    key: 'x-frame-options',
    description: 'Prevents your site from being embedded in other websites\' iframes.',
    impact: 'Without this, attackers can overlay your site in a hidden frame to trick users into clicking things they don\'t intend (clickjacking).',
    fix: 'Add: X-Frame-Options: SAMEORIGIN',
  },
  {
    name: 'X-Content-Type-Options',
    key: 'x-content-type-options',
    description: 'Prevents browsers from guessing the content type of files.',
    impact: 'Without this, browsers might misinterpret uploaded files as executable code.',
    fix: 'Add: X-Content-Type-Options: nosniff',
  },
  {
    name: 'Referrer Policy',
    key: 'referrer-policy',
    description: 'Controls how much URL information is shared when visitors click links.',
    impact: 'Without this, sensitive URL parameters (search terms, user IDs) may leak to third-party sites.',
    fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name: 'Permissions Policy',
    key: 'permissions-policy',
    description: 'Controls which browser features (camera, microphone, location) your site can access.',
    impact: 'Without this, malicious third-party scripts embedded in your site could access device features.',
    fix: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
];

export async function scanHeaders(domain: string): Promise<HeadersResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response: Response;
    try {
      response = await fetch(`https://${domain}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    const headers = response.headers;
    const checks: HeaderCheck[] = HEADER_DEFINITIONS.map((def) => {
      const value = headers.get(def.key) ?? undefined;
      return { ...def, found: value !== undefined, value };
    });

    const score = checks.filter((c) => c.found).length;
    const issues = checks.filter((c) => !c.found).map((c) => `Missing ${c.name}: ${c.impact}`);

    const status: HeadersResult['status'] =
      score <= 1
        ? 'critical'
        : score <= 3
        ? 'warning'
        : score <= 5
        ? 'warning'
        : 'pass';

    const summaries: Record<HeadersResult['status'], string> = {
      critical: `Only ${score} of ${HEADER_DEFINITIONS.length} security headers are set. Your site lacks basic browser-level protections.`,
      warning: `${score} of ${HEADER_DEFINITIONS.length} security headers are set. Several browser protections are missing.`,
      pass: `All ${HEADER_DEFINITIONS.length} security headers are properly configured. Your site has strong browser-level protections.`,
      error: 'Could not complete security header scan.',
    };

    return { status, score, maxScore: HEADER_DEFINITIONS.length, checks, issues, summary: summaries[status] };
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return {
      status: 'error',
      score: 0,
      maxScore: HEADER_DEFINITIONS.length,
      checks: HEADER_DEFINITIONS.map((def) => ({ ...def, found: false })),
      issues: [isTimeout ? 'Scan timed out' : 'Could not connect to the website'],
      summary: 'Could not complete security header scan.',
    };
  }
}
