// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

import http from 'http';
import https from 'https';

export interface PinnedResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** Error code set on the rejection when a pinned request times out. */
export const PINNED_TIMEOUT = 'PINNED_TIMEOUT';

/** Cap on response body bytes read (headers-only callers never get near it). */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Issues an HTTP(S) request pinned to a pre-validated IP address.
 *
 * DNS-rebinding (TOCTOU) protection: connecting by hostname would re-resolve
 * DNS at connect time, letting an attacker's nameserver return a public IP
 * for validation and a private one (169.254.169.254, 10.0.0.1, ...) for the
 * actual connection. Instead the TCP connection is opened directly to the
 * address vetted by resolveAndValidate(), while the original hostname is
 * kept for the Host header, TLS SNI (`servername`), and certificate hostname
 * verification. Accepts both IPv4 and IPv6 addresses.
 */
export function pinnedRequest(
  url: URL,
  ip: string,
  options: { method?: 'HEAD' | 'GET'; timeoutMs?: number } = {}
): Promise<PinnedResponse> {
  const { method = 'HEAD', timeoutMs = 10000 } = options;
  const isHttps = url.protocol === 'https:';

  const requestOptions: https.RequestOptions = {
    host: ip, // dial the pinned IP directly — never re-resolve the hostname
    port: url.port ? Number(url.port) : isHttps ? 443 : 80,
    path: `${url.pathname}${url.search}`,
    method,
    // Preserve the original hostname for virtual hosting...
    headers: { Host: url.host },
    timeout: timeoutMs,
  };
  if (isHttps) {
    // ...and for TLS: `servername` drives both SNI and Node's certificate
    // hostname verification, so the certificate is still checked against
    // the domain even though the socket dials the IP.
    requestOptions.servername = url.hostname;
  }

  return new Promise((resolve, reject) => {
    const onResponse = (res: http.IncomingMessage) => {
      let body = '';
      let received = 0;
      res.on('data', (chunk: Buffer) => {
        received += chunk.length;
        if (received > MAX_BODY_BYTES) {
          // Oversized body: stop reading and return what we have.
          res.destroy();
          resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body });
          return;
        }
        body += chunk.toString('utf8');
      });
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body }));
      res.on('error', reject);
    };

    const req = isHttps
      ? https.request(requestOptions, onResponse)
      : http.request(requestOptions, onResponse);

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Request timed out'), { code: PINNED_TIMEOUT }));
    });
    req.end();
  });
}
