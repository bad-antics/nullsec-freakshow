"""
🎭 changeling CLI (Python) — Git Repository Secrets Scanner
"""

import os
import click
from changeling_py.engine import scan_repo

SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🔵"}
SEV_COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan"}


@click.command()
@click.argument("path", default=".")
@click.option("-n", "--max-commits", type=int, default=None, help="Max commits to scan")
@click.version_option(version="1.0.0", prog_name="changeling-py")
def cli(path, max_commits):
    """🎭 nullsec-changeling (Python) — Git Secrets Scanner"""
    path = os.path.abspath(path)

    if not os.path.isdir(os.path.join(path, ".git")):
        click.echo(f"  ❌ Not a git repository: {path}")
        return

    click.echo()
    click.echo("🎭  CHANGELING (Python) — Git Secrets Scanner")
    click.echo("═══════════════════════════════════════")
    click.echo(f"  Target: {path}")

    findings, scanned = scan_repo(path, max_commits)

    click.echo(f"  Commits scanned: {scanned}")
    click.echo("  ─────────────────────────────────────")

    if not findings:
        click.echo(f"\n  ✅ No secrets found in {scanned} commits\n")
        return

    click.echo(f"\n  🚨 {len(findings)} secrets found:\n")

    for f in findings:
        icon = SEV_ICONS.get(f.severity, "⚪")
        color = SEV_COLORS.get(f.severity, "white")
        click.echo(f"    {icon} ", nl=False)
        click.secho(f"[{f.severity}]", fg=color, nl=False)
        click.echo(f" {f.pattern_name}")
        click.echo(f"      Commit: {f.commit} ({f.author}, {f.date})")
        click.echo(f"      File:   {f.file}")
        click.echo(f"      Match:  {f.match}")
        click.echo()

    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    click.echo("  ─────────────────────────────────────")
    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med = by_sev.get("MEDIUM", 0)
    click.echo(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}")
    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
