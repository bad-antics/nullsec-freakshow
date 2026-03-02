# 🔧 nullsec-kobold — HTTP Header Security Auditor (Node.js)

Part of the **nullsec freakshow** security toolkit.

## What It Does

Kobold audits HTTP security headers — CSP, HSTS, X-Frame-Options,
Referrer-Policy, cookie flags, and information disclosure headers.
Gives a letter grade (A-F) based on header compliance.

## Commands

| Command | Description |
|---------|-------------|
| `kobold <url>` | Audit security headers of a URL |
| `kobold <url1> <url2>` | Audit multiple URLs |

## Install

```bash
cd nullsec-kobold && chmod +x kobold.js && sudo ln -sf $(pwd)/kobold.js /usr/local/bin/kobold
```

## Language

**Node.js** — zero dependencies, uses built-in http/https modules.

## License

MIT — bad-antics / nullsec 2026
