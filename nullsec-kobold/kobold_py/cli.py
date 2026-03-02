"""
🔧 kobold CLI (Python) — HTTP Header Security Auditor
"""

import click
from kobold_py.engine import audit_url


GRADE_COLORS = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}


@click.command()
@click.argument("urls", nargs=-1, required=True)
@click.version_option(version="1.0.0", prog_name="kobold-py")
def cli(urls):
    """🔧 nullsec-kobold (Python) — HTTP Header Security Auditor

    Audit one or more URLs for security header configuration.
    """
    for url in urls:
        click.echo()
        click.echo("🔧  KOBOLD (Python) — Header Security Audit")
        click.echo("═══════════════════════════════════════")
        click.echo(f"  Target: {url}")

        result = audit_url(url)

        if result.error:
            click.secho(f"  ❌ Error: {result.error}", fg="red")
            continue

        click.echo(f"  Status: {result.status_code}")
        click.echo()

        # Group findings
        missing = [f for f in result.findings if f.status == "missing"]
        present = [f for f in result.findings if f.status == "present"]
        info = [f for f in result.findings if f.status == "info"]

        if present:
            click.echo("  ✅ Security Headers Present:")
            for f in present:
                click.echo(f"    ✅ {f.header}: {f.detail}")

        if missing:
            click.echo(f"\n  ❌ Missing Security Headers ({len(missing)}):")
            for f in missing:
                color = "red" if f.severity == "HIGH" else "yellow"
                click.echo(f"    ", nl=False)
                click.secho(f"[{f.severity}]", fg=color, nl=False)
                click.echo(f" {f.detail}")

        if info:
            click.echo(f"\n  ⚠️  Information Disclosure:")
            for f in info:
                click.echo(f"    🟡 {f.detail}")

        click.echo(f"\n  ─────────────────────────────────────")
        click.echo(f"  Score: {result.score}/100  ", nl=False)
        click.secho(f"Grade: {result.grade}", fg=GRADE_COLORS.get(result.grade, "white"), bold=True)
        click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
