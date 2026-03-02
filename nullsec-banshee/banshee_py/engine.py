"""
💀 banshee engine (Python) — File Integrity Screamer
SHA-256 file integrity baselining and verification.
"""

import hashlib
import os
import json
from pathlib import Path
from dataclasses import dataclass


BASELINE_FILE = ".banshee-baseline"


@dataclass
class IntegrityResult:
    modified: list  # (path, old_hash, new_hash)
    deleted: list   # (path, old_hash)
    new_files: list # (path, hash)


def hash_file(path: str) -> str:
    """SHA-256 hash a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except (PermissionError, OSError):
        return ""
    return h.hexdigest()


def create_baseline(directory: str) -> dict[str, str]:
    """Walk directory and hash all files, save baseline."""
    baseline = {}
    root = Path(directory).resolve()

    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root)
            if rel.startswith(".banshee"):
                continue
            h = hash_file(fpath)
            if h:
                baseline[rel] = h

    # Save baseline
    baseline_path = os.path.join(str(root), BASELINE_FILE)
    with open(baseline_path, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)

    return baseline


def check_integrity(directory: str) -> IntegrityResult:
    """Check files against saved baseline."""
    root = Path(directory).resolve()
    baseline_path = os.path.join(str(root), BASELINE_FILE)

    if not os.path.isfile(baseline_path):
        raise FileNotFoundError(f"No baseline found at {baseline_path}. Run 'banshee-py baseline' first.")

    with open(baseline_path) as f:
        baseline = json.load(f)

    modified = []
    deleted = []
    new_files = []

    # Check existing baseline entries
    for rel, old_hash in baseline.items():
        fpath = os.path.join(str(root), rel)
        if not os.path.isfile(fpath):
            deleted.append((rel, old_hash))
        else:
            new_hash = hash_file(fpath)
            if new_hash and new_hash != old_hash:
                modified.append((rel, old_hash, new_hash))

    # Check for new files
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root)
            if rel.startswith(".banshee"):
                continue
            if rel not in baseline:
                h = hash_file(fpath)
                if h:
                    new_files.append((rel, h))

    return IntegrityResult(modified=modified, deleted=deleted, new_files=new_files)
