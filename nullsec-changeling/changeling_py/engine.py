"""
🎭 changeling engine (Python) — Git Repository Secrets Scanner
Scans git commit history for leaked secrets and credentials.
"""

import re
import subprocess
from dataclasses import dataclass


SECRET_PATTERNS = [
    ("AWS Access Key",     "CRITICAL", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",     "CRITICAL", re.compile(r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I)),
    ("GitHub Token",       "CRITICAL", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("GitHub OAuth",       "CRITICAL", re.compile(r"gho_[A-Za-z0-9_]{36,}")),
    ("Generic API Key",    "HIGH",     re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,})", re.I)),
    ("Generic Secret",     "HIGH",     re.compile(r"(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.I)),
    ("Private Key",        "CRITICAL", re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----")),
    ("Slack Token",        "CRITICAL", re.compile(r"xox[bpras]-[A-Za-z0-9\-]{10,}")),
    ("Slack Webhook",      "HIGH",     re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}")),
    ("Google API Key",     "HIGH",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("JWT Token",          "MEDIUM",   re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Stripe Key",         "CRITICAL", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    ("SendGrid Key",       "CRITICAL", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("Database URL",       "CRITICAL", re.compile(r"(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@[^\s'\"]+", re.I)),
    (".env Assignment",    "MEDIUM",   re.compile(r"^[A-Z_]{3,}=(?:['\"])?(?:sk_|pk_|key_|secret_|password|token)", re.I | re.M)),
    ("IP + Credentials",   "HIGH",     re.compile(r"https?://[^:]+:[^@]+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
]

DANGEROUS_FILES = [
    (".env",               "HIGH",     re.compile(r"^\.env(?:\.\w+)?$")),
    ("Private Key File",   "CRITICAL", re.compile(r"\.pem$")),
    ("PKCS12 Keystore",    "CRITICAL", re.compile(r"\.p12$")),
    ("KeePass DB",         "CRITICAL", re.compile(r"\.kdbx?$")),
    ("htpasswd",           "HIGH",     re.compile(r"\.htpasswd$")),
    ("id_rsa/ed25519",     "CRITICAL", re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)$")),
]


@dataclass
class Finding:
    commit: str
    author: str
    date: str
    file: str
    pattern_name: str
    severity: str
    match: str


def scan_repo(path: str, max_commits: int | None = None) -> tuple[list[Finding], int]:
    """Scan git repository for secrets."""
    cmd = f"git -C '{path}' log --all --format='%H|%an|%ai' --diff-filter=ACMR"
    if max_commits:
        cmd += f" -n {max_commits}"

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    commits = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]

    findings = []
    seen = set()

    for entry in commits:
        parts = entry.split("|", 2)
        if len(parts) < 3:
            continue
        sha, author, date = parts

        # Get diff
        diff = subprocess.run(
            f"git -C '{path}' diff-tree -p {sha}",
            shell=True, capture_output=True, text=True
        ).stdout

        current_file = None
        for line in diff.split("\n"):
            if line.startswith("diff --git"):
                m = re.search(r"b/(.+)$", line)
                if m:
                    current_file = m.group(1)
                continue

            if not line.startswith("+") or line.startswith("+++"):
                continue
            if not current_file:
                continue

            content = line[1:]
            for name, sev, pattern in SECRET_PATTERNS:
                m = pattern.search(content)
                if m:
                    key = f"{sha[:8]}:{current_file}:{name}"
                    if key not in seen:
                        seen.add(key)
                        matched = m.group(0)
                        redacted = matched[:6] + "***" + matched[-4:] if len(matched) > 12 else "***"
                        findings.append(Finding(
                            commit=sha[:8], author=author, date=date,
                            file=current_file, pattern_name=name,
                            severity=sev, match=redacted,
                        ))

        # Check filenames
        files_out = subprocess.run(
            f"git -C '{path}' diff-tree --no-commit-id --name-only -r {sha}",
            shell=True, capture_output=True, text=True
        ).stdout

        for fname in files_out.strip().split("\n"):
            fname = fname.strip()
            if not fname:
                continue
            basename = fname.rsplit("/", 1)[-1]
            for name, sev, pattern in DANGEROUS_FILES:
                if pattern.search(basename):
                    key = f"{sha[:8]}:{fname}:{name}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            commit=sha[:8], author=author, date=date,
                            file=fname, pattern_name=name,
                            severity=sev, match=basename,
                        ))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 9), f.date))

    return findings, len(commits)
