"""
👻 phantom engine (Python) — Web Shell Detector
Regex-based PHP/script file scanning for web shell signatures,
obfuscation patterns, and entropy anomalies.
"""

import math
import os
import re
from dataclasses import dataclass, field

# Web shell signature patterns
SHELL_SIGNATURES = [
    # Direct execution
    (re.compile(r'\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', re.I), "eval() with superglobal", 10),
    (re.compile(r'\beval\s*\(\s*base64_decode\s*\(', re.I), "eval(base64_decode())", 10),
    (re.compile(r'\beval\s*\(\s*gzinflate\s*\(', re.I), "eval(gzinflate())", 10),
    (re.compile(r'\beval\s*\(\s*str_rot13\s*\(', re.I), "eval(str_rot13())", 9),
    (re.compile(r'\beval\s*\(\s*gzuncompress\s*\(', re.I), "eval(gzuncompress())", 10),
    (re.compile(r'\bassert\s*\(\s*\$_(GET|POST|REQUEST)', re.I), "assert() with superglobal", 10),

    # System execution
    (re.compile(r'\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$', re.I), "system exec with variable", 9),
    (re.compile(r'`\s*\$_(GET|POST|REQUEST|COOKIE)', re.I), "backtick exec with superglobal", 10),
    (re.compile(r'\bpcntl_exec\s*\(', re.I), "pcntl_exec()", 8),

    # Obfuscation
    (re.compile(r'\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)', re.I), "chr() concatenation chain", 7),
    (re.compile(r'\$\w+\s*\(\s*\$\w+\s*\)', re.I), "variable function call", 5),
    (re.compile(r'preg_replace\s*\(\s*["\'].*\/e["\']', re.I), "preg_replace /e modifier", 9),
    (re.compile(r'create_function\s*\(', re.I), "create_function()", 8),
    (re.compile(r'\bcall_user_func(_array)?\s*\(\s*\$', re.I), "call_user_func with variable", 7),

    # File operations
    (re.compile(r'\bfile_put_contents\s*\(.*\$_(GET|POST|REQUEST)', re.I), "file write from superglobal", 9),
    (re.compile(r'\bfwrite\s*\(.*\$_(GET|POST|REQUEST)', re.I), "fwrite from superglobal", 9),
    (re.compile(r'\bmove_uploaded_file\s*\(', re.I), "file upload handler", 5),

    # Network
    (re.compile(r'\bfsockopen\s*\(', re.I), "fsockopen()", 6),
    (re.compile(r'\bcurl_exec\s*\(', re.I), "curl_exec()", 4),
    (re.compile(r'\bsocket_create\s*\(', re.I), "raw socket creation", 7),

    # Encoding/Decoding chains
    (re.compile(r'base64_decode\s*\(\s*base64_decode', re.I), "double base64 decode", 9),
    (re.compile(r'(\\x[0-9a-f]{2}){10,}', re.I), "hex-encoded string (10+ chars)", 7),
    (re.compile(r'\bgzinflate\s*\(\s*base64_decode\s*\(', re.I), "gzinflate(base64_decode())", 9),

    # Suspicious patterns
    (re.compile(r'\$\w+\s*=\s*str_replace\s*\(.*\$\w+\s*\)', re.I), "string obfuscation via str_replace", 6),
    (re.compile(r'ini_set\s*\(\s*["\']disable_functions["\']', re.I), "disable_functions bypass attempt", 10),
    (re.compile(r'\barray_map\s*\(\s*["\']assert["\']', re.I), "array_map assert trick", 9),

    # C99/r57 shell markers
    (re.compile(r'(c99|r57|b374k|wso|alfa|filesman)', re.I), "known shell name reference", 10),
    (re.compile(r'Web\s*Shell|WebShell|web_shell', re.I), "web shell self-reference", 8),

    # Python/JSP/ASP patterns (for polyglot detection)
    (re.compile(r'os\.system\s*\(\s*request\b', re.I), "Python os.system with request", 9),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\(', re.I), "Java Runtime.exec()", 9),
    (re.compile(r'<%\s*execute\s*request\s*\(', re.I), "ASP execute request", 10),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht",
    ".inc", ".cgi", ".pl", ".py", ".jsp", ".jspx", ".asp", ".aspx",
    ".cfm", ".shtml",
}


@dataclass
class Finding:
    file: str
    line: int
    pattern: str
    severity: int
    snippet: str


@dataclass
class ScanResult:
    file: str
    findings: list[Finding] = field(default_factory=list)
    entropy: float = 0.0
    size: int = 0
    suspicious: bool = False


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def scan_file(filepath: str) -> ScanResult:
    """Scan a single file for web shell signatures."""
    result = ScanResult(file=filepath)

    try:
        stat = os.stat(filepath)
        result.size = stat.st_size
    except OSError:
        return result

    # Skip files > 10MB
    if result.size > 10 * 1024 * 1024:
        return result

    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError):
        return result

    # Calculate entropy
    result.entropy = shannon_entropy(content)

    # High entropy alone is suspicious (> 5.5 for code files)
    if result.entropy > 5.5:
        result.findings.append(Finding(
            file=filepath,
            line=0,
            pattern="HIGH_ENTROPY",
            severity=6,
            snippet=f"Shannon entropy: {result.entropy:.2f} (threshold: 5.5)"
        ))

    # Check each line against signatures
    lines = content.split("\n")
    for lineno, line in enumerate(lines, 1):
        for pattern, name, severity in SHELL_SIGNATURES:
            if pattern.search(line):
                # Truncate long lines
                snippet = line.strip()[:120]
                result.findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    pattern=name,
                    severity=severity,
                    snippet=snippet
                ))

    # Check for very long lines (common in obfuscated shells)
    for lineno, line in enumerate(lines, 1):
        if len(line) > 5000:
            result.findings.append(Finding(
                file=filepath,
                line=lineno,
                pattern="OBFUSCATED_LINE",
                severity=7,
                snippet=f"Line length: {len(line)} chars (threshold: 5000)"
            ))

    result.suspicious = len(result.findings) > 0
    return result


def scan_directory(directory: str, extensions: set[str] | None = None) -> list[ScanResult]:
    """Recursively scan a directory for web shells."""
    if extensions is None:
        extensions = SCAN_EXTENSIONS

    results = []
    for dirpath, _, filenames in os.walk(directory):
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions or not extensions:
                fpath = os.path.join(dirpath, fname)
                if os.path.isfile(fpath):
                    result = scan_file(fpath)
                    if result.suspicious:
                        results.append(result)

    results.sort(key=lambda r: max((f.severity for f in r.findings), default=0), reverse=True)
    return results
