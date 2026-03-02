# 🐈 nullsec-familiar

**Log Pattern Extractor** — Perl

Part of the **nullsec freakshow** suite.

## What It Does

Familiar mines log files and text data for security-relevant patterns using Perl's regex engine:

- **10 pattern types**: IPv4, IPv6, email, URL, MAC, file paths, errors, credentials, ports, usernames
- **Severity ranking**: CRITICAL (credentials) → HIGH (errors) → MEDIUM (emails/URLs) → LOW (IPs/MACs)
- **Recursive scanning**: walks directories, skips binary files
- **Frequency analysis**: shows most common matches first

## Usage

```bash
familiar extract /var/log/syslog                    # Extract all patterns
familiar extract /var/log/ --type ipv4,error         # Filter by type
familiar extract /var/log/auth.log --top 10          # Top 10 per type
familiar summary /var/log/                           # Quick count summary
familiar --help                                      # Help
```

## Pattern Types

| Type | Severity | Description |
|------|----------|-------------|
| cred | CRITICAL | Passwords, tokens, secrets |
| error | HIGH | Errors, failures, exceptions |
| email | MEDIUM | Email addresses |
| url | MEDIUM | HTTP/HTTPS URLs |
| user | MEDIUM | Usernames, login names |
| ipv4 | LOW | IPv4 addresses |
| ipv6 | LOW | IPv6 addresses |
| mac | LOW | MAC addresses |
| path | LOW | System file paths |
| port | LOW | Port numbers |

## Install

```bash
chmod +x familiar.pl
sudo ln -sf $(pwd)/familiar.pl /usr/local/bin/familiar
```

## Language

Pure Perl — no CPAN modules required. Uses only core modules (File::Find, Getopt::Long).

## License

MIT — bad-antics / nullsec
