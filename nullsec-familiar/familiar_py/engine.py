"""
🐈 familiar engine (Python) — Log Pattern Extractor
Regex-heavy log mining for IPs, emails, URLs, errors, credentials, etc.
"""

import re
import os
from collections import defaultdict
from dataclasses import dataclass


PATTERNS = {
    "ipv4":  re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    "ipv6":  re.compile(r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b"),
    "email": re.compile(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"),
    "url":   re.compile(r"(https?://[^\s'\"<>)]+)"),
    "mac":   re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b"),
    "path":  re.compile(r"(/(?:etc|var|tmp|home|usr|opt|root)/[^\s:'\"]+)"),
    "error": re.compile(r"((?:error|fail(?:ed|ure)?|exception|critical|panic|fatal|denied|refused|timeout|unauthorized|forbidden)[\s:].{0,120})", re.I),
    "cred":  re.compile(r"((?:password|passwd|pwd|token|secret|key|credential|auth)[\s]*[=:]\s*\S+)", re.I),
    "port":  re.compile(r"\b(?:port|listening on|:)[\s]*(\d{2,5})\b", re.I),
    "user":  re.compile(r"(?:user(?:name)?|login|uid|account)[\s]*[=:][\s]*['\"]?([a-zA-Z0-9._\-]+)", re.I),
}

SEVERITY = {
    "cred": "CRITICAL", "error": "HIGH", "email": "MEDIUM", "url": "MEDIUM",
    "user": "MEDIUM", "ipv4": "LOW", "ipv6": "LOW", "mac": "LOW",
    "path": "LOW", "port": "LOW",
}

BINARY_EXTS = {".gz", ".bz2", ".xz", ".zip", ".tar", ".bin", ".so", ".png", ".jpg", ".exe", ".pdf"}


@dataclass
class Match:
    file: str
    line: int
    sample: str


def is_text_file(path: str) -> bool:
    """Check if file is likely text."""
    _, ext = os.path.splitext(path)
    if ext.lower() in BINARY_EXTS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        return b"\x00" not in chunk
    except (PermissionError, OSError):
        return False


def extract_from_file(path: str, types: list[str]) -> dict[str, dict[str, list[Match]]]:
    """Extract patterns from a single file."""
    results: dict[str, dict[str, list[Match]]] = defaultdict(lambda: defaultdict(list))

    try:
        with open(path, "r", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip()
                for ptype in types:
                    pattern = PATTERNS[ptype]
                    for m in pattern.finditer(line):
                        match_val = m.group(1) if m.lastindex else m.group(0)
                        if not match_val or len(match_val) < 3:
                            continue

                        # Validate IPv4
                        if ptype == "ipv4":
                            if match_val in ("127.0.0.1", "0.0.0.0"):
                                continue
                            octets = match_val.split(".")
                            if any(int(o) > 255 for o in octets):
                                continue

                        # Validate port
                        if ptype == "port":
                            p = int(match_val)
                            if p < 1 or p > 65535:
                                continue

                        results[ptype][match_val].append(Match(
                            file=path, line=lineno, sample=line[:120]
                        ))
    except (PermissionError, OSError):
        pass

    return results


def extract_from_path(path: str, types: list[str]) -> tuple[dict, int]:
    """Extract patterns from a file or directory."""
    all_results: dict[str, dict[str, list[Match]]] = defaultdict(lambda: defaultdict(list))
    file_count = 0

    if os.path.isfile(path):
        if is_text_file(path):
            file_count = 1
            for ptype, matches in extract_from_file(path, types).items():
                for val, match_list in matches.items():
                    all_results[ptype][val].extend(match_list)
    elif os.path.isdir(path):
        for dirpath, _, filenames in os.walk(path):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                if not is_text_file(fpath):
                    continue
                file_count += 1
                for ptype, matches in extract_from_file(fpath, types).items():
                    for val, match_list in matches.items():
                        all_results[ptype][val].extend(match_list)

    return dict(all_results), file_count
