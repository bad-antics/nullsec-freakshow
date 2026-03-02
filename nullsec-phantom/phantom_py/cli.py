"""
👻 phantom CLI (Python) — Web Shell Detector
"""

import click
import os

from phantom_py.engine import scan_file, scan_directory, SCAN_EXTENSIONS


SEVERITY_COLORS = {
    10: "red",
    9: "red",
    8: "bright_red",
    7: "yellow",
    6: "yellow",
    5: "bright_yellow",
    4: "cyan",
    3: "cyan",
    2: "white",
    1: "white",
    0: "white",
}


@click.group()
@click.version_option()
def main():
    """👻 phantom-py — Web Shell Detector (Python fallback)"""
    pass


@main.command()
@click.argument("path")
@click.option("-a", "--all-files", is_flag=True, help="Scan all file types, not just web extensions")
@click.option("-v", "--verbose", is_flag=True, help="Show clean files too")
def scan(path, all_files, verbose):
    """Scan a file or directory for web shell signatures."""
    click.secho("\n👻 phantom-py — Web Shell Detector\n", fg="magenta", bold=True)

    extensions = set() if all_files else SCAN_EXTENSIONS

    if os.path.isfile(path):
        result = scan_file(path)
        _print_result(result)
    elif os.path.isdir(path):
        click.echo(f"  Scanning: {path}")
        click.echo(f"  Extensions: {'ALL' if all_files else ', '.join(sorted(extensions))}")
        click.echo()

        results = scan_directory(path, extensions)

        if not results:
            click.secho("  ✓ No web shells detected!", fg="green")
            return

        total_findings = 0
        for r in results:
            _print_result(r)
            total_findings += len(r.findings)

        click.echo(f"\n  ═══════════════════════════════════════")
        click.secho(f"  Suspicious files : {len(results)}", fg="red")
        click.secho(f"  Total findings   : {total_findings}", fg="yellow")

        # Severity breakdown
        crit = sum(1 for r in results for f in r.findings if f.severity >= 9)
        high = sum(1 for r in results for f in r.findings if 7 <= f.severity < 9)
        med = sum(1 for r in results for f in r.findings if 4 <= f.severity < 7)
        low = sum(1 for r in results for f in r.findings if f.severity < 4)

        if crit:
            click.secho(f"  CRITICAL         : {crit}", fg="red", bold=True)
        if high:
            click.secho(f"  HIGH             : {high}", fg="bright_red")
        if med:
            click.secho(f"  MEDIUM           : {med}", fg="yellow")
        if low:
            click.secho(f"  LOW              : {low}", fg="cyan")
    else:
        click.secho(f"  ✗ Path not found: {path}", fg="red")
        raise SystemExit(1)


@main.command()
def signatures():
    """List all detection signatures."""
    from phantom_py.engine import SHELL_SIGNATURES

    click.secho("\n👻 phantom-py — Detection Signatures\n", fg="magenta", bold=True)
    click.echo(f"  {'Severity':<10} {'Pattern'}")
    click.echo(f"  {'─' * 10} {'─' * 50}")

    sigs = sorted(SHELL_SIGNATURES, key=lambda s: s[2], reverse=True)
    for _, name, sev in sigs:
        color = SEVERITY_COLORS.get(sev, "white")
        click.secho(f"  [{sev:>2}/10]    {name}", fg=color)

    click.echo(f"\n  Total signatures: {len(sigs)}")


def _print_result(result):
    """Pretty-print a scan result."""
    if not result.findings:
        return

    max_sev = max(f.severity for f in result.findings)
    color = SEVERITY_COLORS.get(max_sev, "white")

    click.secho(f"  ⚠ {result.file}", fg=color, bold=True)
    click.echo(f"    Entropy: {result.entropy:.2f} | Size: {result.size} bytes | Findings: {len(result.findings)}")

    for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        loc = f"L{f.line}" if f.line > 0 else "file"
        click.secho(f"    [{f.severity:>2}/10] {f.pattern} ({loc})", fg=sev_color)
        if f.snippet and f.line > 0:
            click.echo(f"           {f.snippet[:100]}")
    click.echo()


if __name__ == "__main__":
    main()
