# 👁️ nullsec-specter

**SSH Config & Key Auditor** — Bash

Part of the **nullsec freakshow** suite.

## What It Does

Specter audits your SSH configuration for security weaknesses:

- **sshd_config** — checks PermitRootLogin, PasswordAuthentication, port, protocol, X11, MaxAuthTries, agent forwarding
- **SSH keys** — detects weak key types (DSA), short RSA keys, missing passphrases, bad permissions
- **authorized_keys** — permissions, command restrictions
- **known_hosts** — hashing status

## Usage

```bash
specter scan       # Full SSH audit
specter --help     # Help
```

## Severity Levels

| Level | Meaning |
|-------|---------|
| 🔴 CRITICAL | Immediate security risk |
| 🟡 HIGH | Significant weakness |
| 🟡 MEDIUM | Should be addressed |
| 🟡 LOW | Hardening recommendation |
| ✅ | Passed |

## Install

```bash
chmod +x specter.sh
sudo ln -sf $(pwd)/specter.sh /usr/local/bin/specter
```

## Language

Pure Bash — no dependencies beyond coreutils and openssh-client.

## License

MIT — bad-antics / nullsec
