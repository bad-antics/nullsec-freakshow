"""
🔧 kobold engine (Python) — HTTP Header Security Auditor
Checks security headers, info disclosure, and cookie security.
"""

import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "HIGH", "Enforces HTTPS connections"),
    "content-security-policy": ("CSP", "HIGH", "Prevents XSS and injection attacks"),
    "x-content-type-options": ("X-CTO", "MEDIUM", "Prevents MIME-type sniffing"),
    "x-frame-options": ("X-FO", "MEDIUM", "Prevents clickjacking"),
    "x-xss-protection": ("X-XSS", "LOW", "Legacy XSS filter"),
    "referrer-policy": ("Referrer", "MEDIUM", "Controls referrer information"),
    "permissions-policy": ("Perms", "MEDIUM", "Controls browser feature access"),
    "x-permitted-cross-domain-policies": ("X-PCDP", "LOW", "Controls cross-domain policy"),
}

INFO_DISCLOSURE_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish",
]


@dataclass
class HeaderFinding:
    header: str
    severity: str
    status: str  # "present", "missing", "info"
    detail: str = ""


@dataclass
class AuditResult:
    url: str
    status_code: int = 0
    findings: list = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    error: str = ""


def audit_url(url: str) -> AuditResult:
    """Audit HTTP headers for a URL."""
    result = AuditResult(url=url)

    if not url.startswith("http"):
        url = f"https://{url}"
        result.url = url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "nullsec-kobold/1.0.0")
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        result.status_code = resp.getcode()
        headers = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        result.status_code = e.code
        headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        result.error = str(e)
        return result

    score = 100

    # Check security headers
    for header, (name, severity, desc) in SECURITY_HEADERS.items():
        if header in headers:
            result.findings.append(HeaderFinding(
                header=name, severity="OK", status="present",
                detail=f"{header}: {headers[header][:60]}"
            ))
        else:
            if severity == "HIGH":
                score -= 15
            elif severity == "MEDIUM":
                score -= 10
            else:
                score -= 5
            result.findings.append(HeaderFinding(
                header=name, severity=severity, status="missing",
                detail=f"Missing {header} — {desc}"
            ))

    # Check info disclosure
    for header in INFO_DISCLOSURE_HEADERS:
        if header in headers:
            score -= 5
            result.findings.append(HeaderFinding(
                header=header, severity="MEDIUM", status="info",
                detail=f"Info leak: {header}: {headers[header]}"
            ))

    # Check cookies
    cookies = headers.get("set-cookie", "")
    if cookies:
        cookie_lower = cookies.lower()
        if "secure" not in cookie_lower:
            score -= 5
            result.findings.append(HeaderFinding(
                header="Cookie", severity="HIGH", status="info",
                detail="Cookie missing Secure flag"
            ))
        if "httponly" not in cookie_lower:
            score -= 5
            result.findings.append(HeaderFinding(
                header="Cookie", severity="MEDIUM", status="info",
                detail="Cookie missing HttpOnly flag"
            ))
        if "samesite" not in cookie_lower:
            score -= 3
            result.findings.append(HeaderFinding(
                header="Cookie", severity="MEDIUM", status="info",
                detail="Cookie missing SameSite attribute"
            ))

    result.score = max(0, score)
    if score >= 90:
        result.grade = "A"
    elif score >= 75:
        result.grade = "B"
    elif score >= 60:
        result.grade = "C"
    elif score >= 40:
        result.grade = "D"
    else:
        result.grade = "F"

    return result
