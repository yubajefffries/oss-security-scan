// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import https from 'https';
import http from 'http';
import tls from 'tls';

import { pickConnectAddress, resolveAndValidate } from '../validate-domain';

export interface SSLResult {
  status: 'pass' | 'warning' | 'critical' | 'error';
  valid: boolean;
  expiryDays?: number;
  validFrom?: string;
  validTo?: string;
  issuer?: string;
  subject?: string;
  redirectsToHttps?: boolean;
  tlsVersion?: string;
  issues: string[];
  summary: string;
}

/**
 * Checks whether a wildcard CN (e.g. "*.example.com") legitimately covers the given hostname.
 * A wildcard covers exactly one label: *.example.com covers sub.example.com but NOT example.com
 * or deep.sub.example.com.
 */
function matchesWildcard(wildcardCN: string, hostname: string): boolean {
  if (!wildcardCN.startsWith('*.')) return false;
  const base = wildcardCN.slice(2); // "example.com"
  const hostParts = hostname.split('.');
  const baseParts = base.split('.');
  // hostname must be exactly one label deeper than the wildcard base
  return (
    hostParts.length === baseParts.length + 1 &&
    hostname.endsWith('.' + base)
  );
}

function getExpiryDays(validTo: string): number {
  const expiry = new Date(validTo);
  const now = new Date();
  return Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

async function checkHttpsRedirect(domain: string, ip: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      // Pinned: dial the validated IP (never re-resolve the hostname) and
      // keep the hostname in the Host header so virtual hosts still answer.
      { host: ip, port: 80, method: 'HEAD', timeout: 5000, headers: { Host: domain } },
      (res) => {
        const location = res.headers.location ?? '';
        resolve(location.startsWith('https://'));
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

export async function scanSSL(domain: string): Promise<SSLResult> {
  // SSRF guard: never open a TCP/TLS connection to a host that resolves to a
  // private/internal address (the literal-string check alone does not stop a
  // public domain pointing at 169.254.169.254 or 10.0.0.1).
  const guard = await resolveAndValidate(domain);
  if (!guard.valid) {
    return {
      status: 'error',
      valid: false,
      issues: [guard.reason ?? 'Domain failed the pre-scan safety check.'],
      summary: 'Could not scan: the domain failed the pre-scan safety check.',
    };
  }

  // IP pinning: dial the vetted address directly so a rebinding nameserver
  // can't swap in a private address between validation and connect. The
  // hostname stays in `servername` for SNI and certificate verification.
  const pinnedIP = pickConnectAddress(guard.addresses);

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: pinnedIP,
        port: 443,
        servername: domain,
        timeout: 10000,
        rejectUnauthorized: false,
      },
      async () => {
        const cert = socket.getPeerCertificate();
        const tlsVersion = socket.getProtocol() ?? 'Unknown';
        socket.end();

        if (!cert || !cert.subject) {
          resolve({
            status: 'critical',
            valid: false,
            issues: ['No SSL certificate found. Your site is not using HTTPS.'],
            summary: 'No SSL/TLS certificate detected. Your site and visitors are at risk.',
          });
          return;
        }

        const issues: string[] = [];
        const expiryDays = getExpiryDays(cert.valid_to);
        const validFrom = cert.valid_from;
        const validTo = cert.valid_to;
        const issuerRaw = cert.issuer?.O ?? cert.issuer?.CN ?? 'Unknown';
        const issuer = Array.isArray(issuerRaw) ? (issuerRaw as string[])[0] : (issuerRaw as string);
        const subjectRaw = cert.subject?.CN ?? domain;
        const subject = Array.isArray(subjectRaw) ? (subjectRaw as string[])[0] : (subjectRaw as string);

        // Bug fix (P1): require BOTH TLS authorization AND non-expired — OR produced false "valid" for self-signed certs
        const authorized = socket.authorized === true;
        const valid = authorized && expiryDays > 0;
        if (!authorized) {
          issues.push('SSL certificate is not trusted by browsers — it may be self-signed or have an invalid certificate chain.');
        }

        // Check expiry
        if (expiryDays < 0) {
          issues.push(`SSL certificate expired ${Math.abs(expiryDays)} days ago. Browsers show a security warning to all visitors.`);
        } else if (expiryDays < 7) {
          issues.push(`SSL certificate expires in ${expiryDays} days — critical! Renew immediately.`);
        } else if (expiryDays < 30) {
          issues.push(`SSL certificate expires in ${expiryDays} days. Schedule renewal soon.`);
        }

        // Check TLS version
        if (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1') {
          issues.push(`Using outdated ${tlsVersion} protocol. Upgrade to TLS 1.2 or 1.3 for proper security.`);
        }

        // Check domain match (Bug fix P2: wildcard CNs must be properly validated, not blindly accepted)
        const subjectAltNames = cert.subjectaltname ?? '';
        const coveredByCN = subject === domain || matchesWildcard(subject, domain);
        // Bug fix: an unbounded substring match (`includes('DNS:' + domain)`) let a
        // SAN like "DNS:example.com.evil.com" cover "example.com". Compare each
        // SAN entry exactly (case-insensitively), with proper wildcard handling.
        const sanEntries = subjectAltNames
          .split(',')
          .map((entry) => entry.trim())
          .filter((entry) => entry.toLowerCase().startsWith('dns:'))
          .map((entry) => entry.slice(4).toLowerCase());
        const coveredBySAN = sanEntries.some(
          (san) => san === domain || matchesWildcard(san, domain)
        );
        if (!coveredByCN && !coveredBySAN) {
          issues.push(`Certificate hostname mismatch: issued for "${subject}" but checking "${domain}".`);
        }

        // Check HTTP→HTTPS redirect
        const redirectsToHttps = await checkHttpsRedirect(domain, pinnedIP).catch(() => false);
        if (!redirectsToHttps) {
          issues.push('HTTP does not redirect to HTTPS — visitors on http:// get an unsecured connection.');
        }

        const status: SSLResult['status'] =
          expiryDays < 0
            ? 'critical'
            : expiryDays < 7 || tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1'
            ? 'critical'
            : expiryDays < 30 || !redirectsToHttps || issues.length > 0
            ? 'warning'
            : 'pass';

        const summaries = {
          critical: 'Your SSL certificate has critical issues. Visitors may see security warnings.',
          warning: 'SSL is active but has issues that should be addressed soon.',
          pass: 'SSL/TLS is properly configured. Connections to your site are encrypted.',
          error: 'Could not complete SSL scan.',
        };

        resolve({
          status,
          valid,
          expiryDays,
          validFrom,
          validTo,
          issuer,
          subject,
          redirectsToHttps,
          tlsVersion,
          issues,
          summary: summaries[status],
        });
      }
    );

    socket.on('error', () => {
      resolve({
        status: 'critical',
        valid: false,
        issues: ['Could not connect via HTTPS. Your site may not support SSL/TLS.'],
        summary: 'SSL/TLS connection failed. Your site may not be secured with HTTPS.',
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        status: 'error',
        valid: false,
        issues: ['SSL check timed out.'],
        summary: 'SSL scan timed out. Could not assess certificate status.',
      });
    });
  });
}
