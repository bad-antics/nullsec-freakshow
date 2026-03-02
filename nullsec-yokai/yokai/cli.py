"""
🏮 nullsec-yokai CLI — Cron & Systemd Timer Auditor
"""

import click
from yokai.engine import YokaiEngine


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟡",
    "MEDIUM": "🔵",
    "LOW": "⚪",
    "INFO": "ℹ️",
}

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "white",
    "INFO": "blue",
}


@click.group()
@click.version_option(version="1.0.0", prog_name="yokai")
def cli():
    """🏮 nullsec-yokai — Cron & Systemd Timer Auditor"""
    pass


@cli.command()
def scan():
    """Full scheduled task audit (cron + systemd + at)."""
    engine = YokaiEngine()

    click.echo()
    click.echo("🏮  YOKAI — Scheduled Task Auditor")
    click.echo("═══════════════════════════════════════")

    findings = engine.full_audit()

    # Separate info from actionable
    info = [f for f in findings if f.severity == "INFO"]
    issues = [f for f in findings if f.severity != "INFO"]

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues.sort(key=lambda f: sev_order.get(f.severity, 9))

    if info:
        click.echo()
        for f in info:
            click.echo(f"  ℹ️  {f.description}")

    if not issues:
        click.echo()
        click.echo("  ✅ No suspicious scheduled tasks found")
        click.echo()
        return

    click.echo()
    click.echo(f"  🚨 {len(issues)} issues found:")
    click.echo()

    for f in issues:
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        color = SEVERITY_COLORS.get(f.severity, "white")
        click.echo(f"    {icon} ", nl=False)
        click.secho(f"[{f.severity}]", fg=color, nl=False)
        click.echo(f" {f.description}")
        click.echo(f"      Source: {f.source}")
        if f.detail:
            click.echo(f"      Detail: {f.detail}")
        click.echo()

    # Summary
    by_sev = {}
    for f in issues:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    click.echo("  ─────────────────────────────────────")
    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med = by_sev.get("MEDIUM", 0)
    low = by_sev.get("LOW", 0)
    click.echo(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    click.echo()


@cli.command()
def cron():
    """Audit crontabs only."""
    engine = YokaiEngine()

    click.echo()
    click.echo("🏮  YOKAI — Crontab Audit")
    click.echo("═══════════════════════════════════════")

    findings = engine.audit_crontabs()
    _print_findings(findings)


@cli.command()
def timers():
    """Audit systemd timers only."""
    engine = YokaiEngine()

    click.echo()
    click.echo("🏮  YOKAI — Systemd Timer Audit")
    click.echo("═══════════════════════════════════════")

    findings = engine.audit_systemd_timers()
    _print_findings(findings)


@cli.command()
def perms():
    """Check cron directory permissions."""
    engine = YokaiEngine()

    click.echo()
    click.echo("🏮  YOKAI — Cron Permissions Audit")
    click.echo("═══════════════════════════════════════")

    findings = engine.audit_permissions()
    _print_findings(findings)


def _print_findings(findings):
    issues = [f for f in findings if f.severity != "INFO"]
    info = [f for f in findings if f.severity == "INFO"]

    for f in info:
        click.echo(f"  ℹ️  {f.description}")

    if not issues:
        click.echo("  ✅ No issues found")
        click.echo()
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues.sort(key=lambda f: sev_order.get(f.severity, 9))

    click.echo()
    for f in issues:
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        color = SEVERITY_COLORS.get(f.severity, "white")
        click.echo(f"    {icon} ", nl=False)
        click.secho(f"[{f.severity}]", fg=color, nl=False)
        click.echo(f" {f.description}")
        click.echo(f"      {f.source}")
        if f.detail:
            click.echo(f"      {f.detail}")
        click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
