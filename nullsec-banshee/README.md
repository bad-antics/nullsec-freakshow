# 💀 nullsec-banshee — File Integrity Screamer (Rust)

Part of the **nullsec freakshow** security toolkit.

## What It Does

Banshee creates SHA-256 baselines of directories and wails when files
have been modified, deleted, or added. Pure Rust — zero external crates.

## Commands

| Command | Description |
|---------|-------------|
| `banshee baseline <dir>` | Create integrity baseline |
| `banshee wail <dir>` | Check for changes (the wailing) |
| `banshee hash <file>` | SHA-256 hash a single file |

## Build & Install

```bash
cd nullsec-banshee && cargo build --release && sudo cp target/release/banshee /usr/local/bin/
```

## Language

**Rust** — zero-dependency SHA-256 implementation, fast recursive directory walking.

## License

MIT — bad-antics / nullsec 2026
