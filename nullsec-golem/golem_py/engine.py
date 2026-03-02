"""
🗿 golem engine (Python) — Memory-Mapped File Hasher
Uses mmap for zero-copy file I/O and multi-threaded SHA-256 hashing.
"""

import hashlib
import mmap
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class FileHash:
    path: str
    hash: str = ""
    size: int = 0
    error: bool = False
    errmsg: str = ""


def hash_file_mmap(path: str) -> FileHash:
    """Hash a file using mmap for zero-copy I/O."""
    result = FileHash(path=path)

    try:
        stat = os.stat(path)
        if not os.path.isfile(path):
            result.error = True
            result.errmsg = "not a regular file"
            return result

        result.size = stat.st_size
        h = hashlib.sha256()

        if stat.st_size == 0:
            result.hash = h.hexdigest()
            return result

        with open(path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Process in chunks for large files
                offset = 0
                chunk_size = 1 << 20  # 1 MB
                while offset < stat.st_size:
                    end = min(offset + chunk_size, stat.st_size)
                    h.update(mm[offset:end])
                    offset = end

        result.hash = h.hexdigest()

    except PermissionError:
        result.error = True
        result.errmsg = "permission denied"
    except OSError as e:
        result.error = True
        result.errmsg = str(e)

    return result


def scan_directory(directory: str, threads: int = 4) -> tuple[list[FileHash], float]:
    """Hash all files in a directory using thread pool."""
    import time

    files = []
    for dirpath, _, filenames in os.walk(directory):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if os.path.isfile(fpath):
                files.append(fpath)

    start = time.monotonic()

    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(hash_file_mmap, f): f for f in files}
        for future in as_completed(futures):
            results.append(future.result())

    elapsed = time.monotonic() - start
    results.sort(key=lambda r: r.path)
    return results, elapsed


def verify_manifest(manifest_path: str) -> tuple[int, int, int]:
    """Verify files against a saved manifest. Returns (ok, changed, missing)."""
    ok = changed = missing = 0

    with open(manifest_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("="):
                continue
            parts = line.split(None, 1)
            if len(parts) < 2 or len(parts[0]) != 64:
                continue

            expected_hash, path = parts
            result = hash_file_mmap(path)

            if result.error:
                missing += 1
                yield ("MISSING", path, expected_hash, "")
            elif result.hash != expected_hash:
                changed += 1
                yield ("CHANGED", path, expected_hash, result.hash)
            else:
                ok += 1
                yield ("OK", path, expected_hash, result.hash)
