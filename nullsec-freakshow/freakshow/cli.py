"""
🎪 Freakshow CLI — The ringmaster of all 40 tools.
Now with Python fallback ports for all multi-language tools.
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
  ║     9 Languages + Python Fallback Ports              ║
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
    click.echo("  " + "─" * 68)
    for i, tool in enumerate(TOOLS, 1):
        native_ok = "✅" if shutil.which(tool["name"]) else "❌"
        lang = tool.get("lang", "Python")
        py_cmd = tool.get("py_cmd")

        # Build status column
        if py_cmd:
            py_ok = "🐍" if shutil.which(py_cmd) else "  "
            status = f"{native_ok}{py_ok}"
        else:
            status = f"{native_ok}  "

        click.echo(f"  {status} {i:2d}. {tool['emoji']} {tool['name']:<15} [{lang:<7}] — {tool['desc']}")

    click.echo("  " + "─" * 68)
    native_count = sum(1 for t in TOOLS if shutil.which(t["name"]))
    py_count = sum(1 for t in TOOLS if t.get("py_cmd") and shutil.which(t["py_cmd"]))
    click.echo(f"\n  🎪 {native_count}/{len(TOOLS)} native tools installed")
    click.echo(f"  🐍 {py_count}/9 Python fallback ports installed")
    click.echo(f"  Legend: ✅=native  🐍=python port\n")


@main.command(name="summon")
@click.argument("tool_name")
@click.option("--python", "-p", "use_python", is_flag=True, help="Force Python fallback version")
def summon(tool_name, use_python):
    """Summon a tool (auto-fallback to Python port if native unavailable)."""
    import subprocess

    tool = next((t for t in TOOLS if t["name"] == tool_name), None)
    if not tool:
        click.echo(f"  ❌ Unknown tool: {tool_name}")
        click.echo(f"  Run 'freakshow roster' to see all tools.")
        return

    py_cmd = tool.get("py_cmd")

    # If --python flag, try Python port first
    if use_python and py_cmd:
        if shutil.which(py_cmd):
            click.secho(f"  �� Using Python fallback: {py_cmd}", fg="cyan")
            subprocess.run([py_cmd, "--help"])
            return
        else:
            click.echo(f"  ❌ Python port {py_cmd} is not installed.")
            return

    # Try native first
    if shutil.which(tool_name):
        subprocess.run([tool_name, "--help"])
        return

    # Fallback to Python port
    if py_cmd and shutil.which(py_cmd):
        click.secho(f"  ⚡ Native {tool['lang']} version not found, using Python fallback: {py_cmd}", fg="yellow")
        subprocess.run([py_cmd, "--help"])
        return

    # Neither available
    click.echo(f"  ❌ {tool_name} is not installed.")
    if py_cmd:
        click.echo(f"  💡 Install native ({tool['lang']}): see {tool['package']}/README.md")
        click.echo(f"  💡 Install Python fallback: pip install -e nullsec-{tool_name}/ (provides {py_cmd})")
    else:
        click.echo(f"  Install: pip install {tool['package']}")


@main.command(name="check")
def check():
    """Check which freakshow tools are installed."""
    click.echo(f"\n🎪 Checking freakshow installation...\n")
    installed = []
    missing = []
    fallback = []

    for tool in TOOLS:
        native = shutil.which(tool["name"])
        py_cmd = tool.get("py_cmd")
        py_ok = shutil.which(py_cmd) if py_cmd else False

        if native:
            installed.append(tool)
        elif py_ok:
            fallback.append(tool)
        else:
            missing.append(tool)

    click.echo(f"  ✅ Native Installed ({len(installed)}):")
    for t in installed:
        lang = t.get("lang", "Python")
        py_cmd = t.get("py_cmd")
        py_tag = " + 🐍" if py_cmd and shutil.which(py_cmd) else ""
        click.echo(f"     {t['emoji']} {t['name']} [{lang}]{py_tag}")

    if fallback:
        click.echo(f"\n  🐍 Python Fallback Only ({len(fallback)}):")
        for t in fallback:
            click.echo(f"     {t['emoji']} {t['name']} [{t['lang']}] → {t['py_cmd']}")

    if missing:
        click.echo(f"\n  ❌ Missing ({len(missing)}):")
        for t in missing:
            lang = t.get("lang", "Python")
            click.echo(f"     {t['emoji']} {t['name']} [{lang}]")

    total_usable = len(installed) + len(fallback)
    click.echo(f"\n  🎪 {total_usable}/{len(TOOLS)} tools usable ({len(installed)} native, {len(fallback)} fallback).\n")


@main.command(name="ports")
def ports():
    """Show status of all Python fallback ports."""
    click.echo(BANNER)
    click.echo("  🐍 Python Fallback Ports:")
    click.echo("  " + "─" * 58)
    click.echo(f"  {'Status':<8} {'Tool':<15} {'Native':<10} {'Python Port':<15} {'Desc'}")
    click.echo("  " + "─" * 58)

    for tool in TOOLS:
        py_cmd = tool.get("py_cmd")
        if not py_cmd:
            continue

        native_ok = bool(shutil.which(tool["name"]))
        py_ok = bool(shutil.which(py_cmd))

        if native_ok and py_ok:
            status = "✅🐍"
            color = "green"
        elif native_ok:
            status = "✅  "
            color = "cyan"
        elif py_ok:
            status = "  🐍"
            color = "yellow"
        else:
            status = "❌  "
            color = "red"

        click.secho(f"  {status}   {tool['name']:<15} [{tool['lang']:<7}]  {py_cmd:<15} {tool['desc']}", fg=color)

    click.echo("  " + "─" * 58)
    native_count = sum(1 for t in TOOLS if t.get("py_cmd") and shutil.which(t["name"]))
    py_count = sum(1 for t in TOOLS if t.get("py_cmd") and shutil.which(t["py_cmd"]))
    click.echo(f"\n  Native: {native_count}/9 | Python ports: {py_count}/9")
    click.echo(f"  Legend: ✅=native compiled  🐍=python fallback\n")


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
            py_tag = f" (+ {t['py_cmd']})" if t.get("py_cmd") else ""
            click.echo(f"    {t['emoji']} {t['name']}{py_tag}")
    click.echo()

    # Python port summary
    py_tools = [t for t in TOOLS if t.get("py_cmd")]
    click.echo(f"  🐍 {len(py_tools)} tools have Python fallback ports")
    click.echo(f"     Use 'freakshow ports' for detailed port status\n")


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
    click.echo("  All 9 non-Python tools also have Python fallback ports,")
    click.echo("  so you can use every tool without needing compilers.")
    click.echo("  Native versions are faster; Python ports are portable.")
    click.echo()
    click.echo("  Use 'freakshow summon <tool>' — it auto-detects the best")
    click.echo("  version available (native first, Python fallback second).")
    click.echo("  Add --python / -p to force the Python port.")
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
