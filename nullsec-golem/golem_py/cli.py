"""
🗿 golem CLI (Python) — Memory-Mapped File Hasher
"""

import click
import os

from golem_py.engine import hash_file_mmap, scan_directory, verify_manifest


@click.group()
@click.version_option()
def main():
    """🗿 golem-py — Memory-Mapped File Hasher (Python fallback)"""
    pass


@main.command()
@click.argument("filepath")
def hash(filepath):
    """Hash a single file using mmap."""
    if not os.path.exists(filepath):
        click.secho(f"✗ File not found: {filepath}", fg="red")
        raise SystemExit(1)

    result = hash_file_mmap(filepath)

    if result.error:
        click.secho(f"✗ Error: {result.errmsg}", fg="red")
        raise SystemExit(1)

    click.echo(f"  File  : {result.path}")
    click.echo(f"  Size  : {_human_size(result.size)}")
    click.secho(f"  SHA256: {result.hash}", fg="cyan")


@main.command()
@click.argument("directory")
@click.option("-t", "--threads", default=4, help="Worker thread count")
@click.option("-o", "--output", default=None, help="Save manifest to file")
def scan(directory, threads, output):
    """Hash all files in a directory (parallel)."""
    if not os.path.isdir(directory):
        click.secho(f"✗ Not a directory: {directory}", fg="red")
        raise SystemExit(1)

    click.secho(f"\n🗿 golem-py — scanning {directory}", fg="green", bold=True)
    click.echo(f"  Threads: {threads}\n")

    results, elapsed = scan_directory(directory, threads)

    total_size = 0
    errors = 0
    lines = []

    for r in results:
        if r.error:
            click.secho(f"  ✗ {r.errmsg}: {r.path}", fg="red")
            errors += 1
        else:
            click.echo(f"  {r.hash}  {r.path}")
            total_size += r.size
            lines.append(f"{r.hash}  {r.path}")

    click.echo()
    click.echo(f"  ═══════════════════════════════════════")
    click.echo(f"  Files hashed : {len(results) - errors}")
    click.echo(f"  Errors       : {errors}")
    click.echo(f"  Total size   : {_human_size(total_size)}")
    click.secho(f"  Elapsed      : {elapsed:.3f}s", fg="cyan")

    rate = total_size / elapsed if elapsed > 0 else 0
    click.echo(f"  Throughput   : {_human_size(int(rate))}/s")

    if output:
        with open(output, "w") as f:
            f.write(f"# golem-py manifest — {directory}\n")
            for line in lines:
                f.write(line + "\n")
        click.secho(f"\n  ✓ Manifest saved to {output}", fg="green")


@main.command()
@click.argument("manifest")
def verify(manifest):
    """Verify files against a saved manifest."""
    if not os.path.exists(manifest):
        click.secho(f"✗ Manifest not found: {manifest}", fg="red")
        raise SystemExit(1)

    click.secho(f"\n🗿 golem-py — verifying against {manifest}\n", fg="green", bold=True)

    ok = changed = missing = 0
    for status, path, expected, actual in verify_manifest(manifest):
        if status == "OK":
            click.secho(f"  ✓ {path}", fg="green")
            ok += 1
        elif status == "CHANGED":
            click.secho(f"  ✗ CHANGED: {path}", fg="red")
            click.echo(f"    expected: {expected}")
            click.echo(f"    actual  : {actual}")
            changed += 1
        elif status == "MISSING":
            click.secho(f"  ? MISSING: {path}", fg="yellow")
            missing += 1

    click.echo(f"\n  ═══════════════════════════════════════")
    click.secho(f"  OK      : {ok}", fg="green")
    if changed:
        click.secho(f"  Changed : {changed}", fg="red")
    if missing:
        click.secho(f"  Missing : {missing}", fg="yellow")

    if changed or missing:
        raise SystemExit(1)


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


if __name__ == "__main__":
    main()
