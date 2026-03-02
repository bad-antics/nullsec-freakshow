"""
🏮 nullsec-yokai engine — Cron & Systemd Timer Auditor
Audits scheduled tasks for persistence, misconfigurations,
and suspicious entries.
"""

import os
import re
import glob
import subprocess
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Finding:
    source: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    detail: str = ""
    user: str = ""


# ── Suspicious patterns ──────────────────────────────────

SUSPICIOUS_COMMANDS = [
    (r"\bcurl\b.*\|\s*(?:bash|sh|python|perl)", "CRITICAL", "Pipe from curl to shell"),
    (r"\bwget\b.*\|\s*(?:bash|sh|python|perl)", "CRITICAL", "Pipe from wget to shell"),
    (r"\bnc\b.*-[el]", "CRITICAL", "Netcat listener (possible reverse shell)"),
    (r"\bncat\b.*--exec", "CRITICAL", "Ncat with exec (reverse shell)"),
    (r"\bbase64\s+-d\b", "HIGH", "Base64 decode in scheduled task"),
    (r"\beval\b", "HIGH", "eval in scheduled task"),
    (r"\b(?:python|perl|ruby)\s+-e\b", "HIGH", "Inline script execution"),
    (r"\bchmod\s+[47][0-7]{2}\b", "MEDIUM", "Permissions change in cron"),
    (r"\bchown\b.*root", "MEDIUM", "Ownership change to root"),
    (r"/dev/(?:tcp|udp)/", "CRITICAL", "Bash /dev/tcp reverse shell"),
    (r"\bsocat\b", "HIGH", "Socat (possible tunnel/relay)"),
    (r"\bssh\b.*-R\b", "HIGH", "SSH reverse tunnel"),
    (r"\biptables\b.*-[ADIF]", "MEDIUM", "Firewall modification in cron"),
    (r"\buseradd\b|\bgroupadd\b", "HIGH", "User/group creation in cron"),
    (r"\bpasswd\b", "HIGH", "Password change in cron"),
    (r"\brm\s+-rf\s+/", "HIGH", "Recursive delete from root"),
    (r"@reboot", "MEDIUM", "@reboot entry (persistence mechanism)"),
    (r"\* \* \* \* \*", "MEDIUM", "Runs every minute"),
]

WRITABLE_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]


class YokaiEngine:
    """Cron & Systemd timer auditor."""

    def __init__(self):
        self.findings: list[Finding] = []

    def audit_crontabs(self) -> list[Finding]:
        """Audit system and user crontabs."""
        findings = []

        # System crontab
        if os.path.isfile("/etc/crontab"):
            findings.extend(self._scan_crontab("/etc/crontab", "system"))

        # cron.d directory
        cron_d = "/etc/cron.d"
        if os.path.isdir(cron_d):
            for f in os.listdir(cron_d):
                fp = os.path.join(cron_d, f)
                if os.path.isfile(fp):
                    findings.extend(self._scan_crontab(fp, "cron.d"))

        # User crontabs
        for cron_dir in ["/var/spool/cron", "/var/spool/cron/crontabs"]:
            if os.path.isdir(cron_dir):
                try:
                    for user in os.listdir(cron_dir):
                        fp = os.path.join(cron_dir, user)
                        if os.path.isfile(fp):
                            findings.extend(self._scan_crontab(fp, f"user:{user}"))
                except PermissionError:
                    findings.append(Finding(
                        source=cron_dir,
                        severity="LOW",
                        description="Cannot read user crontabs (need root)",
                    ))

        # Periodic directories
        for period in ["daily", "hourly", "weekly", "monthly"]:
            d = f"/etc/cron.{period}"
            if os.path.isdir(d):
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp):
                        findings.extend(self._scan_script(fp, f"cron.{period}"))

        return findings

    def _scan_crontab(self, path: str, source: str) -> list[Finding]:
        """Scan a crontab file for suspicious entries."""
        findings = []
        try:
            with open(path, "r", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for pattern, severity, desc in SUSPICIOUS_COMMANDS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(Finding(
                                source=f"{path}:{lineno}",
                                severity=severity,
                                description=desc,
                                detail=line[:120],
                            ))
        except PermissionError:
            findings.append(Finding(
                source=path,
                severity="LOW",
                description="Cannot read (permission denied)",
            ))
        return findings

    def _scan_script(self, path: str, source: str) -> list[Finding]:
        """Scan a cron script for suspicious commands."""
        findings = []
        try:
            with open(path, "r", errors="replace") as fh:
                content = fh.read()
                for pattern, severity, desc in SUSPICIOUS_COMMANDS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append(Finding(
                            source=f"{path} ({source})",
                            severity=severity,
                            description=desc,
                            detail=matches[0][:80] if matches else "",
                        ))
        except PermissionError:
            pass
        return findings

    def audit_systemd_timers(self) -> list[Finding]:
        """Audit systemd timer units."""
        findings = []
        timer_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
            str(Path.home() / ".config/systemd/user"),
        ]

        for tdir in timer_dirs:
            if not os.path.isdir(tdir):
                continue
            for entry in glob.glob(os.path.join(tdir, "*.timer")):
                findings.extend(self._audit_timer(entry))

        # Check for active timers
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                timer_count = len([l for l in result.stdout.strip().split("\n") if l.strip()])
                findings.append(Finding(
                    source="systemctl",
                    severity="INFO",
                    description=f"{timer_count} active timers found",
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return findings

    def _audit_timer(self, timer_path: str) -> list[Finding]:
        """Audit a single timer unit file."""
        findings = []
        try:
            with open(timer_path, "r") as fh:
                content = fh.read()

            # Check for very frequent execution
            if re.search(r"OnCalendar\s*=\s*\*:\*", content):
                findings.append(Finding(
                    source=timer_path,
                    severity="MEDIUM",
                    description="Timer fires every minute",
                ))

            if re.search(r"OnBootSec\s*=\s*[0-5]s", content):
                findings.append(Finding(
                    source=timer_path,
                    severity="MEDIUM",
                    description="Timer fires within 5s of boot (persistence?)",
                ))

            # Find corresponding service file
            service_name = re.search(r"Unit\s*=\s*(\S+)", content)
            if not service_name:
                service_name = os.path.basename(timer_path).replace(".timer", ".service")
            else:
                service_name = service_name.group(1)

            service_path = os.path.join(os.path.dirname(timer_path), service_name)
            if os.path.isfile(service_path):
                findings.extend(self._audit_service(service_path))

        except PermissionError:
            pass
        return findings

    def _audit_service(self, service_path: str) -> list[Finding]:
        """Audit a service file for suspicious ExecStart."""
        findings = []
        try:
            with open(service_path, "r") as fh:
                content = fh.read()

            # Extract ExecStart lines
            for match in re.finditer(r"ExecStart\s*=\s*(.+)", content):
                cmd = match.group(1).strip()
                for pattern, severity, desc in SUSPICIOUS_COMMANDS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        findings.append(Finding(
                            source=service_path,
                            severity=severity,
                            description=f"Timer service: {desc}",
                            detail=cmd[:120],
                        ))
        except PermissionError:
            pass
        return findings

    def audit_permissions(self) -> list[Finding]:
        """Check permissions on cron directories and files."""
        findings = []

        for d in WRITABLE_CRON_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                st = os.stat(d)
                mode = oct(st.st_mode)[-3:]
                if int(mode[2]) & 2:  # world-writable
                    findings.append(Finding(
                        source=d,
                        severity="CRITICAL",
                        description=f"Cron directory is world-writable ({mode})",
                    ))
                elif int(mode[1]) & 2:  # group-writable
                    findings.append(Finding(
                        source=d,
                        severity="HIGH",
                        description=f"Cron directory is group-writable ({mode})",
                    ))
            except PermissionError:
                pass

        # Check /etc/crontab permissions
        if os.path.isfile("/etc/crontab"):
            try:
                st = os.stat("/etc/crontab")
                mode = oct(st.st_mode)[-3:]
                if mode != "644" and mode != "600":
                    findings.append(Finding(
                        source="/etc/crontab",
                        severity="MEDIUM",
                        description=f"Unusual permissions: {mode} (expected 644 or 600)",
                    ))
            except PermissionError:
                pass

        return findings

    def audit_at_jobs(self) -> list[Finding]:
        """Audit at jobs queue."""
        findings = []
        at_spool = "/var/spool/at"
        if os.path.isdir(at_spool):
            try:
                jobs = [f for f in os.listdir(at_spool) if not f.startswith(".")]
                if jobs:
                    findings.append(Finding(
                        source=at_spool,
                        severity="MEDIUM",
                        description=f"{len(jobs)} pending at jobs found",
                    ))
                    for job in jobs[:5]:
                        fp = os.path.join(at_spool, job)
                        findings.extend(self._scan_script(fp, "at-job"))
            except PermissionError:
                pass
        return findings

    def full_audit(self) -> list[Finding]:
        """Run complete audit."""
        self.findings = []
        self.findings.extend(self.audit_crontabs())
        self.findings.extend(self.audit_systemd_timers())
        self.findings.extend(self.audit_permissions())
        self.findings.extend(self.audit_at_jobs())
        return self.findings
