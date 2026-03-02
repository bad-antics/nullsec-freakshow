"""
👻 poltergeist CLI (Python) — /proc Anomaly Detector
"""

import click
from poltergeist_py.engine import full_scan, get_readdir_pids, get_process_info


@click.group()
@click.version_option(version="1.0.0", prog_name="poltergeist-py")
def cli():
    """👻 nullsec-poltergeist (Python) — /proc Anomaly Detector"""
    pass


@cli.command()
@click.option("--bruteforce/--no-bruteforce", default=False,
              help="Enable brute-force PID detection (slower)")
def scan(bruteforce):
    """Full anomaly scan (hidden PIDs, deleted exes, RWX)."""
    click.echo()
    click.echo("👻  POLTERGEIST (Python) — /proc Anomaly Scan")
    click.echo("═══════════════════════════════════════")

    report = full_scan(bruteforce=bruteforce)

    click.echo(f"  Visible processes: {report.total_procs}")

    # Hidden PIDs
    if bruteforce:
        click.echo(f"\n  🔍 Hidden PID Detection (brute-force):")
        if report.hidden_pids:
            for info in report.hidden_pids:
                click.secho(f"    🔴 PID {info.pid} ({info.name}) — HIDDEN!", fg="red")
        else:
            click.echo("    ✅ No hidden processes found")

    # Deleted exes
    click.echo(f"\n  💀 Deleted Executables:")
    if report.deleted_exes:
        for info in report.deleted_exes:
            click.secho(f"    🟡 PID {info.pid} ({info.name}) — {info.exe}", fg="yellow")
    else:
        click.echo("    ✅ None found")

    # RWX mappings
    click.echo(f"\n  🛡️ Anonymous RWX Memory Mappings:")
    if report.rwx_mappings:
        for info in report.rwx_mappings:
            click.secho(f"    🔴 PID {info.pid} ({info.name}) — {len(info.rwx_maps)} RWX regions", fg="red")
            for addr in info.rwx_maps[:3]:
                click.echo(f"        {addr}")
    else:
        click.echo("    ✅ None found")

    total = len(report.hidden_pids) + len(report.deleted_exes) + len(report.rwx_mappings)
    click.echo(f"\n  ─────────────────────────────────────")
    if total > 0:
        click.secho(f"  ⚠️  {total} anomalies detected", fg="red")
    else:
        click.echo("  ✅ System looks clean")
    click.echo()


@cli.command()
def pids():
    """List all visible processes."""
    click.echo()
    click.echo("👻  POLTERGEIST (Python) — Process List")
    click.echo("═══════════════════════════════════════")

    pids = sorted(get_readdir_pids())
    for pid in pids:
        info = get_process_info(pid)
        click.echo(f"  {pid:>6}  {info.name:<20} {info.state}")

    click.echo(f"\n  Total: {len(pids)} processes\n")


def main():
    cli()


if __name__ == "__main__":
    main()
