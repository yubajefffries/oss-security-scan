# Open Source Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

An all-in-one domain and email security scanner. One scan runs four phases: DNS foundation, email authentication (SPF/DKIM/DMARC), email blocklist status, and security headers.

Built by [DarkHorse IT](https://darkhorseit.com). "Audit the audit" — full transparency by design.

## What It Scans

| Phase | Category | Checks |
|-------|----------|--------|
| 1 | **DNS Foundation** | A, AAAA, MX, TXT, NS records via DNS-over-HTTPS (Cloudflare + Google fallback) |
| 2 | **Email Authentication** | SPF record & policy, DKIM selectors (9 common), DMARC policy & enforcement, A-F grading |
| 3 | **Email Blocklists** | Spamhaus ZEN (with return code classification), Barracuda BRBL, SpamCop, SORBS, UCEPROTECT L1, Abuseat CBL |
| 4 | **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |

## What's Included

This repo contains two layers:

1. **Server-side API scanners** (`api/` + `lib/`) — Next.js API routes that use Node.js built-ins (`dns/promises`, `tls`, `https`) for server-side scanning.
2. **Client-side React components** (`src/`) — Reusable React components that run the DNS, email auth, and blocklist phases entirely in the browser via DNS-over-HTTPS, and call the server-side API only for the security headers phase.

### Client-Side Components

The `src/` directory contains a complete React-based scanner UI:

- **`DomainSecurityScanner`** — Orchestrator component that runs all 4 scan phases with progressive results
- **Section components** — DNS Foundation, Email Auth (with A-F grading), Blacklist Check, Security Headers
- **Shared components** — Domain input with validation, scan progress indicator, copy-to-clipboard, insight cards, best practice badges
- **Libraries** — DNS-over-HTTPS resolver, email auth grader, blacklist checker (all browser-compatible, zero server dependencies)

### Server-Side API

The `api/` + `lib/` directory provides Next.js API routes for scans that require server-side access (SSL/TLS certificate inspection, security headers via direct HTTP).

## Tech Stack

- **Runtime:** Node.js 18+ (server), any modern browser (client)
- **Framework:** Next.js (API routes), React (components)
- **Language:** TypeScript
- **Server dependencies:** None beyond Node.js built-ins (`dns/promises`, `tls`, `https`)
- **Client dependencies:** React, DNS-over-HTTPS (Cloudflare/Google public resolvers)

## Quick Start

```bash
# Clone
git clone https://github.com/yubajefffries/oss-security-scan.git
cd oss-security-scan

# Install
npm install

# Run
npm run dev
```

Then call the API endpoints:

```bash
# Email authentication check
curl -X POST http://localhost:3000/api/scan/email-auth \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# SSL/TLS check
curl -X POST http://localhost:3000/api/scan/ssl \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Security headers check
curl -X POST http://localhost:3000/api/scan/headers \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Blocklist check
curl -X POST http://localhost:3000/api/scan/blacklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Project Structure

```
oss-security-scan/
├── api/scan/                    # Next.js API route handlers
│   ├── email-auth/route.ts
│   ├── ssl/route.ts
│   ├── headers/route.ts
│   └── blacklist/route.ts
├── lib/
│   ├── scanners/                # Server-side scanning logic
│   │   ├── email-auth.ts        # SPF, DKIM, DMARC (via dns/promises)
│   │   ├── ssl.ts               # Certificate & TLS (via tls, https)
│   │   ├── headers.ts           # Security headers (via fetch)
│   │   └── blacklist.ts         # DNSBL queries (via dns/promises)
│   ├── types.ts                 # TypeScript interfaces
│   └── validate-domain.ts       # Input validation & SSRF prevention
├── src/
│   ├── components/
│   │   ├── DomainSecurityScanner.tsx   # Main orchestrator (4-phase scan)
│   │   ├── sections/
│   │   │   ├── DnsFoundationSection.tsx
│   │   │   ├── EmailAuthSection.tsx
│   │   │   ├── BlacklistSection.tsx
│   │   │   ├── HeadersSection.tsx
│   │   │   └── SecuritySummary.tsx
│   │   └── shared/
│   │       ├── BestPracticeBadge.tsx
│   │       ├── CopyButton.tsx
│   │       ├── DomainInput.tsx
│   │       ├── InsightCard.tsx
│   │       └── ScanProgress.tsx
│   ├── lib/
│   │   ├── dns-over-https.ts    # Browser-side DNS resolver (Cloudflare + Google)
│   │   ├── email-auth-grader.ts # A-F grading algorithm
│   │   ├── blacklist-checker.ts # DNSBL checker with false-positive filtering
│   │   └── copy-results.ts     # Clipboard utility
│   └── styles/
│       └── tools.css            # Component styles (CSS custom properties)
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Security

- All domain inputs are validated against SSRF attacks (private IPs, localhost, metadata endpoints blocked)
- Server-side connections are pinned to the DNS-validated IP (hostname kept only for Host/SNI/certificate checks), closing the DNS-rebinding window between validation and connect; redirect targets are re-validated and pinned the same way
- No secrets or API keys required — all checks use public DNS and direct connections
- Client-side DNS uses HTTPS resolvers (Cloudflare, Google) — no raw DNS from the browser
- Rate limiting recommended in production (not included — use your platform's rate limiter)

## License

MIT — see [LICENSE](./LICENSE)
