"""
🎪 Freakshow CLI — The ringmaster of all 40 tools.
"""
import shutil
import click
from . import TOOLS

BANNER = r"""
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║   🎪  T H E   F R E A K S H O W   S U I T E  🎪    ║
  ║                                                      ║
  ║     40 Weird & Creepy Security Tools                 ║
  ║     9 Languages: Python, Go, Rust, C, C++,           ║
  ║     Node.js, Ruby, Perl, PHP, Bash                   ║
  ║     by bad-antics | nullsec@proton.me                ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
"""

@click.group()
def main():
    """🎪 nullsec-freakshow — The Freakshow Suite"""
    pass


@main.command(name="roster")
def roster():
    """Show the full roster of freakshow tools."""
    click.echo(BANNER)
    click.echo("  The Full Roster:")
    click.echo("  " + "─" * 58)
    for i, tool in enumerate(TOOLS, 1):
        installed = "✅" if shutil.which(tool["name"]) else "❌"
        lang = tool.get("lang", "Python")
        click.echo(f"  {installed} {i:2d}. {tool['emoji']} {tool['name']:<15} [{lang:<7}] — {tool['desc']}")
    click.echo("  " + "─" * 58)
    installed_count = sum(1 for t in TOOLS if shutil.which(t["name"]))
    click.echo(f"\n  🎪 {installed_count}/{len(TOOLS)} tools installed.\n")


@main.command(name="summon")
@click.argument("tool_name")
def summon(tool_name):
    """Summon a specific tool by name (runs its --help)."""
    import subprocess
    tool = next((t for t in TOOLS if t["name"] == tool_name), None)
    if not tool:
        click.echo(f"  ❌ Unknown tool: {tool_name}")
        click.echo(f"  Run 'freakshow roster' to see all tools.")
        return
    if not shutil.which(tool_name):
        click.echo(f"  ❌ {tool_name} is not installed.")
        click.echo(f"  Install: {tool['package']}")
        return
    subprocess.run([tool_name, "--help"])


@main.command(name="check")
def check():
    """Check which freakshow tools are installed."""
    click.echo(f"\n🎪 Checking freakshow installation...\n")
    installed = []
    missing = []
    for tool in TOOLS:
        if shutil.which(tool["name"]):
            installed.append(tool)
        else:
            missing.append(tool)

    click.echo(f"  ✅ Installed ({len(installed)}):")
    for t in installed:
        lang = t.get("lang", "Python")
        click.echo(f"     {t['emoji']} {t['name']} [{lang}]")

    if missing:
        click.echo(f"\n  ❌ Missing ({len(missing)}):")
        for t in missing:
            lang = t.get("lang", "Python")
            click.echo(f"     {t['emoji']} {t['name']} [{lang}]")

    click.echo(f"\n  🎪 {len(installed)}/{len(TOOLS)} tools ready.\n")


@main.command(name="languages")
def languages():
    """Show language breakdown."""
    click.echo(BANNER)
    langs = {}
    for tool in TOOLS:
        lang = tool.get("lang", "Python")
        langs.setdefault(lang, []).append(tool)

    click.echo("  Language Breakdown:")
    click.echo("  " + "─" * 40)
    for lang, tools in sorted(langs.items(), key=lambda x: -len(x[1])):
        click.echo(f"  {lang:<10} — {len(tools)} tools")
        for t in tools:
            click.echo(f"    {t['emoji']} {t['name']}")
    click.echo()


@main.command(name="about")
def about():
    """About the freakshow."""
    click.echo(BANNER)
    click.echo("  The Freakshow Suite is a collection of 40 weird and creepy")
    click.echo("  security tools built by bad-antics for the nullsec project.")
    click.echo()
    click.echo("  Written across 9 programming languages: Python, Go, Rust,")
    click.echo("  C, C++, Node.js, Ruby, Perl, PHP, and Bash.")
    click.echo()
    click.echo("  Each tool takes a horror/occult theme and applies it to a")
    click.echo("  real security concept — from steganography to process")
    click.echo("  forensics, from network necromancy to password dark arts.")
    click.echo()
    click.echo("  🔗 https://github.com/bad-antics/nullsec-freakshow")
    click.echo("  📧 nullsec@proton.me")
    click.echo()
    click.echo("  The freakshow never closes. It only moves to the next town.")
    click.echo()


def entry_point():
    main()

if __name__ == "__main__":
    entry_point()
