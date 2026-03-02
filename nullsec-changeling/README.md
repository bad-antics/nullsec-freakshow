# 🎭 nullsec-changeling

**Git Repository Secrets Scanner** — Ruby

Part of the **nullsec freakshow** suite.

## What It Does

Changeling scans git commit history for leaked secrets and credentials:

- **20 secret patterns** — AWS keys, GitHub tokens, Slack tokens, API keys, passwords, private keys, database URLs, Stripe/SendGrid/Twilio keys, JWTs, and more
- **10 dangerous file patterns** — .env, .pem, .p12, id_rsa, credentials, shadow, etc.
- **Full history scan** — examines every commit diff, not just current state
- **Deduplication** — unique findings only
- **Severity ranking** — CRITICAL → HIGH → MEDIUM

## Usage

```bash
changeling scan                 # Scan current repo
changeling scan /path/to/repo   # Scan specific repo
changeling scan . -n 100        # Last 100 commits only
changeling --help               # Help
```

## Install

```bash
chmod +x changeling.rb
sudo ln -sf $(pwd)/changeling.rb /usr/local/bin/changeling
```

## Language

Pure Ruby — no gems required. Needs git on PATH.

## License

MIT — bad-antics / nullsec
