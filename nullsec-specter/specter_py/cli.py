"""
👁️ specter CLI (Python) — SSH Config & Key Auditor
"""

import click
from specter_py.engine import full_audit

SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🔵", "LOW": "⚪", "OK": "✅", "INFO": "ℹ️"}
SEV_COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "white", "OK": "green", "INFO": "blue"}


@click.command()
@click.version_option(version="1.0.0", prog_name="specter-py")
def cli():
    """👁️ nullsec-specter (Python) — SSH Config & Key Auditor"""
    click.echo()
    click.echo("👁️  SPECTER (Python) — SSH Security Audit")
    click.echo("═══════════════════════════════════════")

    findings = full_audit()

    issues = [f for f in findings if f.severity not in ("OK", "INFO")]
    ok = [f for f in findings if f.severity == "OK"]
    info = [f for f in findings if f.severity == "INFO"]

    if ok:
        click.echo("\n  ✅ Passed:")
        for f in ok:
            click.echo(f"    ✅ {f.description}")

    if info:
        click.echo("\n  ℹ️  Info:")
        for f in info:
            click.echo(f"    ℹ️  {f.description}")

    if issues:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        issues.sort(key=lambda f: sev_order.get(f.severity, 9))

        click.echo(f"\n  ⚠️  Issues ({len(issues)}):")
        for f in issues:
            icon = SEV_ICONS.get(f.severity, "⚪")
            color = SEV_COLORS.get(f.severity, "white")
            click.echo(f"    {icon} ", nl=False)
            click.secho(f"[{f.severity}]", fg=color, nl=False)
            click.echo(f" {f.description}")
    else:
        click.echo("\n  ✅ SSH config looks solid")

    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
