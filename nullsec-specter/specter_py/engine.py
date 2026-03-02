"""
👁️ specter engine (Python) — SSH Config & Key Auditor
Audits sshd_config, SSH keys, authorized_keys, and known_hosts.
"""

import os
import re
import glob
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    source: str
    severity: str
    description: str
    detail: str = ""


def audit_sshd_config() -> list[Finding]:
    """Audit sshd_config settings."""
    findings = []

    # Gather config files
    configs = []
    if os.path.isfile("/etc/ssh/sshd_config"):
        configs.append("/etc/ssh/sshd_config")
    for f in glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        configs.append(f)

    if not configs:
        findings.append(Finding("sshd_config", "MEDIUM", "No sshd_config found"))
        return findings

    # Read all directives
    directives = {}
    for conf in configs:
        try:
            with open(conf, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        directives[parts[0].lower()] = parts[1]
        except PermissionError:
            findings.append(Finding(conf, "LOW", f"Cannot read {conf} (permission denied)"))

    # PermitRootLogin
    root_login = directives.get("permitrootlogin", "").lower()
    if root_login == "yes":
        findings.append(Finding("sshd_config", "CRITICAL", "PermitRootLogin yes — root can SSH directly"))
    elif root_login in ("prohibit-password", "without-password"):
        findings.append(Finding("sshd_config", "MEDIUM", f"PermitRootLogin {root_login} — consider 'no'"))
    elif root_login == "no":
        findings.append(Finding("sshd_config", "OK", "PermitRootLogin no"))
    else:
        findings.append(Finding("sshd_config", "MEDIUM", "PermitRootLogin not explicitly set"))

    # PasswordAuthentication
    pass_auth = directives.get("passwordauthentication", "").lower()
    if pass_auth == "yes":
        findings.append(Finding("sshd_config", "HIGH", "PasswordAuthentication yes — brute-force possible"))
    elif pass_auth == "no":
        findings.append(Finding("sshd_config", "OK", "PasswordAuthentication no (key-only)"))
    else:
        findings.append(Finding("sshd_config", "MEDIUM", "PasswordAuthentication not explicitly set"))

    # Port
    port = directives.get("port", "22")
    if port == "22":
        findings.append(Finding("sshd_config", "LOW", "SSH on default port 22"))
    else:
        findings.append(Finding("sshd_config", "OK", f"SSH on non-standard port {port}"))

    # Protocol
    proto = directives.get("protocol", "")
    if proto == "1":
        findings.append(Finding("sshd_config", "CRITICAL", "Protocol 1 enabled — insecure!"))

    # X11Forwarding
    x11 = directives.get("x11forwarding", "").lower()
    if x11 == "yes":
        findings.append(Finding("sshd_config", "LOW", "X11Forwarding enabled"))

    # MaxAuthTries
    max_auth = directives.get("maxauthtries", "")
    if max_auth and max_auth.isdigit() and int(max_auth) > 6:
        findings.append(Finding("sshd_config", "MEDIUM", f"MaxAuthTries={max_auth} (high)"))

    # AllowAgentForwarding
    agent_fwd = directives.get("allowagentforwarding", "yes").lower()
    if agent_fwd == "yes":
        findings.append(Finding("sshd_config", "LOW", "Agent forwarding enabled (lateral movement risk)"))

    return findings


def audit_ssh_keys() -> list[Finding]:
    """Audit SSH keys and authorized_keys."""
    findings = []
    home_dirs = glob.glob("/home/*") + ["/root"]

    for home in home_dirs:
        ssh_dir = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue
        user = os.path.basename(home)

        # Private keys
        for pattern in ["id_*"]:
            for key_path in glob.glob(os.path.join(ssh_dir, pattern)):
                if key_path.endswith(".pub"):
                    continue
                if not os.path.isfile(key_path):
                    continue

                # Permissions
                try:
                    perms = oct(os.stat(key_path).st_mode)[-3:]
                    if perms not in ("600", "400"):
                        findings.append(Finding(key_path, "HIGH",
                                                f"{user}: key permissions {perms} (should be 600)"))
                except OSError:
                    continue

                # Key type and strength
                try:
                    result = subprocess.run(
                        ["ssh-keygen", "-l", "-f", key_path],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        parts = result.stdout.strip()
                        bits_match = re.match(r"(\d+)", parts)
                        type_match = re.search(r"\((\w+)\)", parts)
                        if bits_match and type_match:
                            bits = int(bits_match.group(1))
                            ktype = type_match.group(1)

                            if ktype == "DSA":
                                findings.append(Finding(key_path, "CRITICAL",
                                                        f"{user}: DSA key — deprecated and weak"))
                            elif ktype == "RSA" and bits < 2048:
                                findings.append(Finding(key_path, "HIGH",
                                                        f"{user}: RSA-{bits} — too short"))
                            elif ktype == "RSA" and bits < 4096:
                                findings.append(Finding(key_path, "MEDIUM",
                                                        f"{user}: RSA-{bits} — consider 4096"))
                            else:
                                findings.append(Finding(key_path, "OK",
                                                        f"{user}: {ktype}-{bits}"))
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

                # Passphrase check
                try:
                    with open(key_path, "r") as f:
                        content = f.read()
                    if "ENCRYPTED" in content:
                        findings.append(Finding(key_path, "OK",
                                                f"{user}: key is passphrase-protected"))
                    else:
                        findings.append(Finding(key_path, "MEDIUM",
                                                f"{user}: key has no passphrase"))
                except (PermissionError, OSError):
                    pass

        # authorized_keys
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        if os.path.isfile(auth_keys):
            try:
                perms = oct(os.stat(auth_keys).st_mode)[-3:]
                if perms not in ("600", "644", "400"):
                    findings.append(Finding(auth_keys, "HIGH",
                                            f"{user}: authorized_keys perms {perms}"))

                with open(auth_keys, "r") as f:
                    lines = f.readlines()
                key_count = sum(1 for l in lines if l.strip() and not l.startswith("#"))
                restricted = sum(1 for l in lines if l.strip().startswith("command="))
                findings.append(Finding(auth_keys, "INFO",
                                        f"{user}: {key_count} authorized keys"))
                if key_count > 0 and restricted == 0:
                    findings.append(Finding(auth_keys, "LOW",
                                            f"{user}: no command restrictions on authorized keys"))
            except (PermissionError, OSError):
                pass

    return findings


def audit_known_hosts() -> list[Finding]:
    """Audit known_hosts hashing status."""
    findings = []
    home_dirs = glob.glob("/home/*") + ["/root"]

    for home in home_dirs:
        kh = os.path.join(home, ".ssh", "known_hosts")
        if not os.path.isfile(kh):
            continue
        user = os.path.basename(home)

        try:
            with open(kh, "r") as f:
                lines = f.readlines()
            total = len([l for l in lines if l.strip()])
            hashed = sum(1 for l in lines if l.strip().startswith("|1|"))
            unhashed = total - hashed

            if unhashed > 0:
                findings.append(Finding(kh, "LOW",
                                        f"{user}: {unhashed} unhashed entries in known_hosts"))
            else:
                findings.append(Finding(kh, "OK",
                                        f"{user}: known_hosts is hashed ({total} entries)"))
        except (PermissionError, OSError):
            pass

    return findings


def full_audit() -> list[Finding]:
    """Run complete SSH audit."""
    findings = []
    findings.extend(audit_sshd_config())
    findings.extend(audit_ssh_keys())
    findings.extend(audit_known_hosts())
    return findings
