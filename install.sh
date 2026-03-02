#!/usr/bin/env bash
# ──────────────────────────────────────────────────
# 🎪 Freakshow Suite — Install all 30 tools
# ──────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIP_ARGS=""

# Detect if we need --break-system-packages (Python 3.11+ on Debian/Ubuntu)
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
    if [ ! -d "$VIRTUAL_ENV" ]; then
        PIP_ARGS="--break-system-packages"
    fi
fi

TOOLS=(
    nullsec-sigil
    nullsec-dead-drop
    nullsec-miasma
    nullsec-temporal
    nullsec-hexspeak
    nullsec-whisper
    nullsec-skinwalker
    nullsec-ouija
    nullsec-eidolon
    nullsec-doppelganger
    nullsec-seance
    nullsec-lamprey
    nullsec-voodoo
    nullsec-cryptid
    nullsec-gremlin
    nullsec-grimoire
    nullsec-wendigo
    nullsec-harbinger
    nullsec-revenant
    nullsec-necronomicon
    nullsec-chimera
    nullsec-basilisk
    nullsec-apparition
    nullsec-manticore
    nullsec-ghoul
    nullsec-lich
    nullsec-imp
    nullsec-shade
    nullsec-djinn
    nullsec-mothman
    nullsec-freakshow
)

echo ""
echo "  🎪 Installing The Freakshow Suite — 30 tools"
echo "  ──────────────────────────────────────────────"
echo ""

INSTALLED=0
FAILED=0

for tool in "${TOOLS[@]}"; do
    tool_dir="$SCRIPT_DIR/$tool"
    if [ -d "$tool_dir" ]; then
        printf "  Installing %-25s ... " "$tool"
        if pip install $PIP_ARGS -e "$tool_dir" -q 2>/dev/null; then
            echo "✅"
            ((INSTALLED++))
        else
            echo "❌"
            ((FAILED++))
        fi
    else
        printf "  %-25s ... ⚠️ not found\n" "$tool"
        ((FAILED++))
    fi
done

echo ""
echo "  ──────────────────────────────────────────────"
echo "  🎪 $INSTALLED installed, $FAILED failed"
echo ""

if [ $INSTALLED -gt 0 ]; then
    echo "  Run 'freakshow roster' to see all tools."
    echo ""
fi
