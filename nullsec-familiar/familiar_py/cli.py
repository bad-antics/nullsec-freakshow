"""
🐈 familiar CLI (Python) — Log Pattern Extractor
"""

import click
from familiar_py.engine import extract_from_path, PATTERNS, SEVERITY

SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🔵", "LOW": "⚪"}
SEV_COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "white"}


@click.group()
@click.version_option(version="1.0.0", prog_name="familiar-py")
def cli():
    """🐈 nullsec-familiar (Python) — Log Pattern Extractor"""
    pass


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("--type", "types_str", default=None, help="Comma-separated types: ipv4,email,url,error,cred,etc.")
@click.option("--top", "top_n", default=0, type=int, help="Show top N per type")
def extract(paths, types_str, top_n):
    """Extract patterns from files or directories."""
    if not paths:
        paths = (".",)

    types = types_str.split(",") if types_str else list(PATTERNS.keys())

    click.echo()
    click.echo("🐈  FAMILIAR (Python) — Log Pattern Extractor")
    click.echo("═══════════════════════════════════════")
    click.echo(f"  Targets: {', '.join(paths)}")
    click.echo(f"  Types:   {', '.join(types)}")

    all_results = {}
    total_files = 0
    for path in paths:
        results, count = extract_from_path(path, types)
        total_files += count
        for ptype, matches in results.items():
            if ptype not in all_results:
                all_results[ptype] = {}
            for val, match_list in matches.items():
                all_results.setdefault(ptype, {}).setdefault(val, []).extend(match_list)

    click.echo(f"  Files scanned: {total_files}")
    click.echo("  ─────────────────────────────────────")

    total_findings = 0
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_types = sorted(types, key=lambda t: sev_order.get(SEVERITY.get(t, "LOW"), 9))

    for ptype in sorted_types:
        if ptype not in all_results:
            continue
        data = all_results[ptype]
        sev = SEVERITY.get(ptype, "LOW")
        count = len(data)
        total_findings += count

        icon = SEV_ICONS.get(sev, "⚪")
        color = SEV_COLORS.get(sev, "white")
        click.echo(f"\n  {icon} ", nl=False)
        click.secho(f"{ptype.upper()}", fg=color, nl=False)
        click.echo(f" ({count} unique)")

        sorted_matches = sorted(data.items(), key=lambda x: -len(x[1]))
        if top_n:
            sorted_matches = sorted_matches[:top_n]

        for val, matches in sorted_matches:
            click.echo(f"    {val:<40}  ({len(matches)} occurrences)")
            if len(matches) <= 3:
                click.echo(f"      └─ {matches[0].file}:{matches[0].line}")

    click.echo(f"\n  ─────────────────────────────────────")
    click.echo(f"  Total: {total_findings} unique findings from {total_files} files")
    click.echo()


@cli.command()
@click.argument("paths", nargs=-1)
def summary(paths):
    """Quick count summary of all pattern types."""
    if not paths:
        paths = (".",)

    all_types = list(PATTERNS.keys())

    click.echo()
    click.echo("🐈  FAMILIAR (Python) — Quick Summary")
    click.echo("═══════════════════════════════════════")

    all_results = {}
    total_files = 0
    for path in paths:
        results, count = extract_from_path(path, all_types)
        total_files += count
        for ptype, matches in results.items():
            if ptype not in all_results:
                all_results[ptype] = {}
            for val, match_list in matches.items():
                all_results.setdefault(ptype, {}).setdefault(val, []).extend(match_list)

    click.echo(f"  Files: {total_files}\n")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_types = sorted(all_types, key=lambda t: sev_order.get(SEVERITY.get(t, "LOW"), 9))

    for ptype in sorted_types:
        count = len(all_results.get(ptype, {}))
        sev = SEVERITY.get(ptype, "LOW")
        icon = SEV_ICONS.get(sev, "⚪")
        color = SEV_COLORS.get(sev, "white")
        click.echo(f"    {icon} {ptype:<12} ", nl=False)
        click.secho(f"{sev:<8}", fg=color, nl=False)
        click.echo(f"  {count} unique")

    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
