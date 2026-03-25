/**
 * Validates that a cleaned hostname is a safe, public domain.
 * Rejects private IP ranges, localhost, and bare hostnames to prevent SSRF.
 */

const PRIVATE_IP_RANGES = [
  /^127\./,                          // loopback
  /^10\./,                           // private class A
  /^192\.168\./,                     // private class C
  /^172\.(1[6-9]|2\d|3[01])\./,     // private class B (172.16–172.31)
  /^0\./,                            // "this" network
  /^169\.254\./,                     // link-local
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

export function validateDomain(hostname: string): { valid: boolean; reason?: string } {
  if (!hostname || typeof hostname !== 'string') {
    return { valid: false, reason: 'No hostname provided.' };
  }

  const h = hostname.trim().toLowerCase();

  // Must contain at least one dot (blocks bare hostnames like "internal-server")
  if (!h.includes('.')) {
    return { valid: false, reason: 'Invalid domain: must be a fully qualified domain name.' };
  }

  // Block known localhost names
  if (BLOCKED_HOSTNAMES.has(h)) {
    return { valid: false, reason: 'Scanning internal addresses is not allowed.' };
  }

  // Block private/internal IP ranges
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
