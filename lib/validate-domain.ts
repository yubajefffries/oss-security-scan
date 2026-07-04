/**
 * Validates that a cleaned hostname is a safe, public domain.
 * Rejects private IP ranges, localhost, and bare hostnames to prevent SSRF.
 *
 * Two layers:
 *  - validateDomain(): synchronous, syntactic checks only (charset allowlist,
 *    embedded ports, literal IPs, known-internal hostnames).
 *  - resolveAndValidate(): resolves A/AAAA records and REJECTS if any resolved
 *    address is private / loopback / link-local / CGNAT / cloud-metadata.
 *    Any scanner that actually connects to the host (HTTP fetch, TLS connect)
 *    MUST use this — the literal string check alone does not stop a public
 *    domain that resolves to 169.254.169.254 or 10.0.0.1.
 *
 * Known limitation (documented, not fixed here): there is still a small
 * DNS-rebinding TOCTOU window between resolveAndValidate() and the scanner's
 * own connection, since the OS resolver is queried again at connect time.
 * Closing it fully requires pinning the resolved IP in the connection layer.
 */

import dns from 'dns/promises';
import net from 'net';

const PRIVATE_IP_RANGES = [
  /^127\./,                          // loopback
  /^10\./,                           // private class A
  /^192\.168\./,                     // private class C
  /^172\.(1[6-9]|2\d|3[01])\./,     // private class B (172.16–172.31)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // CGNAT 100.64.0.0/10
  /^0\./,                            // "this" network
  /^169\.254\./,                     // link-local (incl. 169.254.169.254 metadata)
  /^::1$/,                           // IPv6 loopback
  /^fc00:/i,                         // IPv6 unique local
  /^fe80:/i,                         // IPv6 link-local
];

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

/** Blocked IPv4 ranges as [base, prefixLength]. */
const BLOCKED_IPV4_CIDRS: Array<[string, number]> = [
  ['0.0.0.0', 8],       // "this" network
  ['10.0.0.0', 8],      // RFC1918 private
  ['100.64.0.0', 10],   // CGNAT (RFC6598)
  ['127.0.0.0', 8],     // loopback
  ['169.254.0.0', 16],  // link-local, incl. 169.254.169.254 cloud metadata
  ['172.16.0.0', 12],   // RFC1918 private
  ['192.168.0.0', 16],  // RFC1918 private
];

function ipv4ToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function isBlockedIPv4(ip: string): boolean {
  if (!net.isIPv4(ip)) return false;
  const addr = ipv4ToLong(ip);
  return BLOCKED_IPV4_CIDRS.some(([base, bits]) => {
    const mask = ((~0 << (32 - bits)) >>> 0);
    return ((addr & mask) >>> 0) === ((ipv4ToLong(base) & mask) >>> 0);
  });
}

export function isBlockedIPv6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === '::' || s === '::1') return true;          // unspecified / loopback
  // IPv4-mapped addresses (::ffff:10.0.0.1) inherit the IPv4 policy
  const v4match = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4match) return isBlockedIPv4(v4match[1]);
  const firstHextet = s.split(':').find((p) => p.length > 0);
  if (!firstHextet) return true;
  const n = parseInt(firstHextet, 16);
  if (Number.isNaN(n)) return true;                    // unparseable — refuse
  if ((n & 0xfe00) === 0xfc00) return true;            // fc00::/7 unique local
  if ((n & 0xffc0) === 0xfe80) return true;            // fe80::/10 link-local
  return false;
}

/** Returns true if the IP must not be connected to. Unparseable input is treated as blocked. */
export function isBlockedIP(ip: string): boolean {
  if (net.isIPv4(ip)) return isBlockedIPv4(ip);
  if (net.isIPv6(ip)) return isBlockedIPv6(ip);
  return true;
}

export function validateDomain(hostname: string): { valid: boolean; reason?: string } {
  if (!hostname || typeof hostname !== 'string') {
    return { valid: false, reason: 'No hostname provided.' };
  }

  const h = hostname.trim().toLowerCase();

  // Reject embedded ports ("example.com:22") and IPv6 literals outright.
  if (h.includes(':')) {
    return { valid: false, reason: 'Invalid domain: ports and IPv6 literals are not accepted. Enter a hostname only.' };
  }

  // Charset allowlist: letters, digits, dot, hyphen only.
  // Blocks control characters, whitespace, "@", "%"-encoding tricks, etc.
  if (!/^[a-z0-9.-]+$/.test(h)) {
    return { valid: false, reason: 'Invalid domain: only letters, digits, dots, and hyphens are allowed.' };
  }

  // No empty labels (leading/trailing dot, "..")
  if (h.startsWith('.') || h.endsWith('.') || h.includes('..')) {
    return { valid: false, reason: 'Invalid domain: malformed hostname.' };
  }

  // Must contain at least one dot (blocks bare hostnames like "internal-server")
  if (!h.includes('.')) {
    return { valid: false, reason: 'Invalid domain: must be a fully qualified domain name.' };
  }

  // Block known localhost names
  if (BLOCKED_HOSTNAMES.has(h)) {
    return { valid: false, reason: 'Scanning internal addresses is not allowed.' };
  }

  // Block private/internal IP ranges written literally
  for (const pattern of PRIVATE_IP_RANGES) {
    if (pattern.test(h)) {
      return { valid: false, reason: 'Scanning internal addresses is not allowed.' };
    }
  }

  // Block raw IPv4 addresses entirely (not just private — avoids cloud metadata endpoints like 169.254.169.254)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) {
    return { valid: false, reason: 'IP addresses are not accepted. Please enter a domain name.' };
  }

  return { valid: true };
}

/**
 * SSRF guard for scanners that connect to the target: performs the syntactic
 * checks, then resolves A/AAAA and rejects if ANY resolved address is
 * private / loopback / link-local / CGNAT / metadata.
 */
export async function resolveAndValidate(domain: string): Promise<{ valid: boolean; reason?: string }> {
  const syntactic = validateDomain(domain);
  if (!syntactic.valid) return syntactic;

  const h = domain.trim().toLowerCase();

  const [v4, v6] = await Promise.allSettled([dns.resolve4(h), dns.resolve6(h)]);
  const addresses: string[] = [
    ...(v4.status === 'fulfilled' ? v4.value : []),
    ...(v6.status === 'fulfilled' ? v6.value : []),
  ];

  if (addresses.length === 0) {
    return { valid: false, reason: 'Domain does not resolve to any IP address.' };
  }

  for (const ip of addresses) {
    if (isBlockedIP(ip)) {
      return { valid: false, reason: 'Scanning internal addresses is not allowed.' };
    }
  }

  return { valid: true };
}
