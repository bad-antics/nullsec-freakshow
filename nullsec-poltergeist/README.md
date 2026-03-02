# 👻 nullsec-poltergeist — /proc Anomaly Detector (C)

Part of the **nullsec freakshow** security toolkit.

## What It Does

Poltergeist reads /proc directly to detect hidden processes, deleted
executables, and suspicious anonymous RWX memory mappings. Compares
readdir vs brute-force PID enumeration to find rootkit-hidden processes.

## Commands

| Command | Description |
|---------|-------------|
| `poltergeist scan` | Full anomaly scan (hidden PIDs, deleted exes, RWX) |
| `poltergeist pids` | List all visible processes |

## Build & Install

```bash
cd nullsec-poltergeist && make && sudo make install
```

## Language

**C** — direct /proc filesystem access, no dependencies.

## License

MIT — bad-antics / nullsec 2026
