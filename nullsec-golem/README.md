# 🗿 nullsec-golem

**Memory-Mapped File Hasher** — C++

Part of the **nullsec freakshow** suite.

## What It Does

Golem uses mmap for zero-copy file I/O and multi-threaded SHA-256 hashing:

- **mmap-based** — no read() syscalls, no buffer copies
- **Multi-threaded** — std::thread worker pool (auto-detects core count)
- **SHA-256** — custom implementation, zero dependencies
- **Integrity verification** — save hashes to manifest, verify later
- **MADV_SEQUENTIAL** — advises kernel for optimal readahead

## Usage

```bash
golem hash /etc/passwd              # Hash single file
golem scan /etc -t 8                # Hash directory (8 threads)
golem scan /usr/bin > manifest.txt  # Save manifest
golem verify manifest.txt           # Verify integrity
golem --help                        # Help
```

## Build

```bash
make          # Build with g++ -std=c++17 -O2
make install  # Install to /usr/local/bin
make clean    # Remove binary
```

## Language

C++17 — uses `<filesystem>`, `<thread>`, `mmap(2)`. No external libraries.

## License

MIT — bad-antics / nullsec
