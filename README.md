# Open Source Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

An all-in-one domain and email security scanner. One scan checks SSL certificates, email authentication (SPF/DKIM/DMARC), security headers, and email blocklist status.

Built by [DarkHorse IT](https://darkhorseit.com). "Audit the audit" — full transparency by design.

## What It Scans

| Category | Checks |
|----------|--------|
| **Email Authentication** | SPF record, DKIM selectors (13 common), DMARC policy |
| **SSL/TLS** | Certificate validity, expiry, TLS version, HTTP→HTTPS redirect |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Email Blocklists** | Spamhaus ZEN, Barracuda BRBL, SpamCop, SORBS |

## Tech Stack

- **Runtime:** Node.js 18+
- **Framework:** Next.js (API routes)
- **Language:** TypeScript
- **Dependencies:** None beyond Node.js built-ins (`dns/promises`, `tls`, `https`)

## Quick Start

```bash
# Clone
git clone https://github.com/darkhorseit/security-scan.git
cd security-scan

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
├── api/scan/              # Next.js API route handlers
│   ├── email-auth/route.ts
│   ├── ssl/route.ts
│   ├── headers/route.ts
│   └── blacklist/route.ts
├── lib/
│   ├── scanners/          # Core scanning logic
│   │   ├── email-auth.ts  # SPF, DKIM, DMARC
│   │   ├── ssl.ts         # Certificate & TLS
│   │   ├── headers.ts     # Security headers
│   │   └── blacklist.ts   # DNSBL queries
│   ├── types.ts           # TypeScript interfaces
│   └── validate-domain.ts # Input validation & SSRF prevention
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Security

- All domain inputs are validated against SSRF attacks (private IPs, localhost, metadata endpoints blocked)
- No secrets or API keys required — all checks use public DNS and direct connections
- Rate limiting recommended in production (not included — use your platform's rate limiter)

## License

MIT — see [LICENSE](./LICENSE)
