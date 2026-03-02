"""
💀 banshee CLI (Python) — File Integrity Screamer
"""

import click
from banshee_py.engine import hash_file, create_baseline, check_integrity


@click.group()
@click.version_option(version="1.0.0", prog_name="banshee-py")
def cli():
    """💀 nullsec-banshee (Python) — File Integrity Screamer"""
    pass


@cli.command()
@click.argument("directory")
def baseline(directory):
    """Create SHA-256 hash baseline of all files."""
    click.echo()
    click.echo("💀  BANSHEE (Python) — Creating Baseline")
    click.echo("═══════════════════════════════════════")
    click.echo(f"  Directory: {directory}")

    result = create_baseline(directory)

    click.echo(f"  Files hashed: {len(result)}")
    click.echo(f"  Baseline saved to .banshee-baseline")
    click.echo()


@cli.command()
@click.argument("directory")
def wail(directory):
    """Check files against baseline (the wailing)."""
    click.echo()
    click.echo("💀  BANSHEE (Python) — Integrity Check")
    click.echo("═══════════════════════════════════════")

    try:
        result = check_integrity(directory)
    except FileNotFoundError as e:
        click.echo(f"  ❌ {e}")
        return

    if result.modified:
        click.echo(f"\n  🟡 MODIFIED ({len(result.modified)}):")
        for path, old_h, new_h in result.modified:
            click.echo(f"    {path}")
            click.echo(f"      was: {old_h[:16]}...")
            click.echo(f"      now: {new_h[:16]}...")

    if result.deleted:
        click.echo(f"\n  🔴 DELETED ({len(result.deleted)}):")
        for path, old_h in result.deleted:
            click.echo(f"    {path}")

    if result.new_files:
        click.echo(f"\n  🔵 NEW ({len(result.new_files)}):")
        for path, h in result.new_files:
            click.echo(f"    {path}")

    if not result.modified and not result.deleted and not result.new_files:
        click.echo("\n  ✅ All files intact — no changes detected")

    total = len(result.modified) + len(result.deleted) + len(result.new_files)
    click.echo(f"\n  Changes: {total}\n")


@cli.command(name="hash")
@click.argument("filepath")
def hash_cmd(filepath):
    """Hash a single file."""
    h = hash_file(filepath)
    if h:
        click.echo(f"{h}  {filepath}")
    else:
        click.echo(f"  ❌ Cannot hash: {filepath}")


def main():
    cli()


if __name__ == "__main__":
    main()
