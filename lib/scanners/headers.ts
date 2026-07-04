// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import { resolveAndValidate } from '../validate-domain';

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

/** Max redirect hops to follow manually (each hop is re-validated against the SSRF guard). */
const MAX_REDIRECTS = 3;

function errorResult(message: string): HeadersResult {
  return {
    status: 'error',
    score: 0,
    maxScore: HEADER_DEFINITIONS.length,
    checks: HEADER_DEFINITIONS.map((def) => ({ ...def, found: false })),
    issues: [message],
    summary: 'Could not complete security header scan.',
  };
}

export async function scanHeaders(domain: string): Promise<HeadersResult> {
  // SSRF guard: never fetch a host that resolves to a private/internal address.
  const guard = await resolveAndValidate(domain);
  if (!guard.valid) {
    return errorResult(guard.reason ?? 'Domain failed the pre-scan safety check.');
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response: Response | undefined;
    let redirectNote: string | undefined;
    try {
      // SSRF fix: never auto-follow redirects (redirect:'follow' would happily
      // fetch http://169.254.169.254/ if the target 302s there). We follow at
      // most MAX_REDIRECTS hops manually, re-validating every hop's hostname
      // against the same private-address guard before fetching it.
      let url = `https://${domain}`;
      for (let hop = 0; ; hop++) {
        response = await fetch(url, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
        });

        if (response.status < 300 || response.status >= 400) break;

        const location = response.headers.get('location');
        if (!location) break;

        let next: URL;
        try {
          next = new URL(location, url);
        } catch {
          redirectNote = 'Site responded with a redirect to a malformed URL; headers evaluated on the redirect response.';
          break;
        }

        if (next.protocol !== 'https:' && next.protocol !== 'http:') {
          redirectNote = `Site redirects to a non-HTTP(S) URL (${next.protocol}//…); redirect not followed.`;
          break;
        }

        if (next.port && next.port !== '80' && next.port !== '443') {
          redirectNote = `Site redirects to a non-standard port (${next.port}); redirect not followed.`;
          break;
        }

        if (hop >= MAX_REDIRECTS) {
          redirectNote = `Stopped after ${MAX_REDIRECTS} redirects; headers evaluated on the last response received.`;
          break;
        }

        const hopGuard = await resolveAndValidate(next.hostname);
        if (!hopGuard.valid) {
          redirectNote = `Site redirects to "${next.hostname}", which did not pass the safety check — redirect not followed; headers evaluated on the initial response.`;
          break;
        }

        url = next.toString();
      }
    } finally {
      clearTimeout(timeout);
    }

    if (!response) {
      return errorResult('Could not connect to the website');
    }

    const headers = response.headers;
    const checks: HeaderCheck[] = HEADER_DEFINITIONS.map((def) => {
      const value = headers.get(def.key) ?? undefined;
      return { ...def, found: value !== undefined, value };
    });

    const score = checks.filter((c) => c.found).length;
    const issues = checks.filter((c) => !c.found).map((c) => `Missing ${c.name}: ${c.impact}`);
    if (redirectNote) {
      issues.unshift(redirectNote);
    }

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
    return errorResult(isTimeout ? 'Scan timed out' : 'Could not connect to the website');
  }
}
