// DarkHorse IT — Open Source Security Scanner
// https://github.com/darkhorseit/security-scan
// License: MIT
// "Audit the audit" — full transparency by design.

/**
 * Minimal in-memory sliding-window rate limiter for the scan endpoints.
 * Every scan makes this server open DNS lookups and outbound connections on
 * the caller's behalf, so an unthrottled endpoint is a request amplifier.
 *
 * Zero dependencies by design (see README). State lives in module scope, so
 * limits are PER SERVER INSTANCE: on serverless platforms each warm instance
 * counts separately and a cold start resets the windows. That is fine as a
 * safety net — put a real limiter (WAF rules, Redis, your CDN) in front for
 * anything heavier. See README "Rate Limiting".
 */

const WINDOWS = [
  { ms: 60_000, max: 10 },      // 10 scans per minute
  { ms: 3_600_000, max: 100 },  // 100 scans per hour
] as const;

const LONGEST_WINDOW_MS = 3_600_000;

/** Cap on tracked clients so a spoofed-IP flood can't grow memory unbounded. */
const MAX_TRACKED_CLIENTS = 10_000;

/** Request timestamps (ms, oldest first) per client, pruned on every check. */
const clients = new Map<string, number[]>();

/**
 * Extracts the client IP for rate-limit keying: first x-forwarded-for entry,
 * then x-real-ip, then 'unknown'. Both headers are client-forgeable unless a
 * trusted proxy overwrites them; 'unknown' at least lumps header-less
 * callers into one shared bucket instead of letting them bypass the limit.
 */
export function getClientIp(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  if (forwarded) return forwarded;
  const realIp = headers.get('x-real-ip')?.trim();
  if (realIp) return realIp;
  return 'unknown';
}

export type RateLimitDecision =
  | { allowed: true }
  | { allowed: false; retryAfterSeconds: number };

/**
 * Records one request for the client and reports whether it is within every
 * window. Denied requests are not recorded, so a blocked client's window
 * still drains at the normal rate.
 */
export function checkRateLimit(clientIp: string): RateLimitDecision {
  const now = Date.now();
  const cutoff = now - LONGEST_WINDOW_MS;

  const timestamps = (clients.get(clientIp) ?? []).filter((t) => t > cutoff);

  for (const window of WINDOWS) {
    const inWindow = timestamps.filter((t) => t > now - window.ms);
    if (inWindow.length >= window.max) {
      clients.set(clientIp, timestamps);
      // Allowed again once the oldest request in this window ages out.
      const retryAfterSeconds = Math.max(1, Math.ceil((inWindow[0] + window.ms - now) / 1000));
      return { allowed: false, retryAfterSeconds };
    }
  }

  timestamps.push(now);
  if (!clients.has(clientIp) && clients.size >= MAX_TRACKED_CLIENTS) {
    // Soft cap: evict clients whose entire history has aged out before
    // admitting a new one (a full map of genuinely active clients stays).
    for (const [ip, stamps] of clients) {
      if (stamps.length === 0 || stamps[stamps.length - 1] <= cutoff) clients.delete(ip);
    }
  }
  clients.set(clientIp, timestamps);
  return { allowed: true };
}
