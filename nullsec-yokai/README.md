# 🏮 nullsec-yokai

**Cron & Systemd Timer Auditor** — Python

Part of the **nullsec freakshow** suite.

## What It Does

Yokai audits all scheduled tasks for persistence mechanisms and suspicious entries:

- **Crontabs** — /etc/crontab, /etc/cron.d/*, user crontabs, cron.{daily,hourly,weekly,monthly}
- **Systemd timers** — all timer units + their associated service ExecStart commands
- **at jobs** — pending one-shot scheduled tasks
- **Permissions** — world/group-writable cron directories
- **18 suspicious patterns** — curl|bash pipes, reverse shells, netcat, base64 decode, SSH tunnels, user creation, etc.

## Usage

```bash
yokai scan        # Full audit (cron + systemd + at + perms)
yokai cron        # Crontabs only
yokai timers      # Systemd timers only
yokai perms       # Permission check only
yokai --help      # Help
```

## Install

```bash
pip install -e . --break-system-packages
```

## Language

Python 3.10+ with Click CLI framework.

## License

MIT — bad-antics / nullsec
