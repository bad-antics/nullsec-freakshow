"""
👻 wraith CLI (Python) — Ephemeral Port Scanner
"""

import click
import time
from wraith_py.engine import ghost_scan, haunt_scan, SUSPICIOUS_PORTS


@click.group()
@click.version_option(version="1.0.0", prog_name="wraith-py")
def cli():
    """👻 nullsec-wraith (Python) — Ephemeral Port Scanner"""
    pass


@cli.command()
@click.argument("host")
@click.argument("port_range", default="1-1024")
@click.option("-w", "--workers", default=100, help="Concurrent workers")
@click.option("-t", "--timeout", default=1.0, help="Timeout per port (seconds)")
def scan(host, port_range, workers, timeout):
    """Scan ports on a host."""
    parts = port_range.split("-")
    start_port = int(parts[0])
    end_port = int(parts[1]) if len(parts) > 1 else start_port

    click.echo()
    click.echo("👻  WRAITH (Python) — Port Scanner")
    click.echo("═══════════════════════════════════════")
    click.echo(f"  Target: {host}")
    click.echo(f"  Range:  {start_port}-{end_port}")
    click.echo(f"  Workers: {workers}")

    t0 = time.monotonic()
    results = ghost_scan(host, start_port, end_port, workers, timeout)
    elapsed = time.monotonic() - t0

    click.echo(f"\n  🔓 {len(results)} open ports found in {elapsed:.1f}s:\n")

    for r in results:
        marker = "  ⚠️ " if r.suspicious else "    "
        svc = r.service or "unknown"
        click.echo(f"{marker}{r.port:<8} {svc:<20} {r.latency_ms:.0f}ms")

    suspicious = [r for r in results if r.suspicious]
    if suspicious:
        click.echo(f"\n  ⚠️  {len(suspicious)} suspicious ports detected!")

    click.echo()


@cli.command()
@click.argument("host")
@click.argument("rounds", default=3, type=int)
@click.option("-w", "--workers", default=100, help="Concurrent workers")
def haunt(host, rounds, workers):
    """Multi-round scan to detect ephemeral ports."""
    click.echo()
    click.echo("👻  WRAITH (Python) — Ephemeral Port Detection")
    click.echo("═══════════════════════════════════════")
    click.echo(f"  Target: {host}")
    click.echo(f"  Rounds: {rounds}")

    result = haunt_scan(host, 1, 1024, rounds, workers)

    if result["stable"]:
        click.echo(f"\n  🔒 Stable ports ({len(result['stable'])}):")
        for p in result["stable"]:
            svc = p["service"] or "unknown"
            click.echo(f"    {p['port']:<8} {svc:<20} ({p['rounds']}/{rounds} rounds)")

    if result["ephemeral"]:
        click.echo(f"\n  👻 Ephemeral ports ({len(result['ephemeral'])}):")
        for p in result["ephemeral"]:
            svc = p["service"] or "unknown"
            click.echo(f"    {p['port']:<8} {svc:<20} ({p['rounds']}/{rounds} rounds)")

    if not result["stable"] and not result["ephemeral"]:
        click.echo("\n  No open ports found.")

    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
