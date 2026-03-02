# 👻 nullsec-wraith — Ephemeral Port Scanner (Go)

Part of the **nullsec freakshow** security toolkit.

## What It Does

Wraith scans for open ports and detects ephemeral listeners — ports that
appear and vanish like ghosts. Identifies backdoor ports and suspicious services.

## Commands

| Command | Description |
|---------|-------------|
| `wraith scan <host> [range]` | Scan ports on a target host |
| `wraith haunt <host> [rounds]` | Multi-round scan for ephemeral port detection |
| `wraith --json scan <host>` | JSON output mode |

## Build & Install

```bash
cd nullsec-wraith && go build -o wraith . && sudo mv wraith /usr/local/bin/
```

## Language

**Go** — concurrent port scanning with goroutine worker pool.

## License

MIT — bad-antics / nullsec 2026
