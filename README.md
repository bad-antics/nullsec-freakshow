# 🎪 nullsec-freakshow

## **The Freakshow Suite — 30 Weird & Creepy Security CLI Tools**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![bad-antics](https://img.shields.io/badge/by-bad--antics-red.svg)](https://github.com/bad-antics)
[![Tools](https://img.shields.io/badge/tools-30-red.svg)](https://github.com/bad-antics/nullsec-freakshow)

> *Step right up. The show is about to begin. What you see here cannot be unseen.*

Every tool is a standalone Python CLI built with [Click](https://click.palletsprojects.com/). Install one, install all — each has its own `setup.py`, README, and entry point.

---

## 🎭 The Full Roster

| # | Tool | Command | Description |
|---|------|---------|-------------|
| 1 | 🔮 **Sigil** | `sigil` | Visual hash fingerprinting — turns any hash into geometric SVG art |
| 2 | 📦 **Dead Drop** | `dead-drop` | LSB steganography — hide AES-256 encrypted messages in PNG images |
| 3 | 🎲 **Miasma** | `miasma` | Shannon entropy analyzer — detect stego, weak crypto, packed malware |
| 4 | ⏰ **Temporal** | `temporal` | Filesystem forensic timestamp analyzer — detect timestomping |
| 5 | 🔢 **Hexspeak** | `hexspeak` | Hex word encoder/decoder with 150+ word dictionary & poetry |
| 6 | 👁️ **Whisper** | `whisper` | Spectral audio steganography — voices hidden in spectrograms |
| 7 | 🐺 **Skinwalker** | `skinwalker` | Process mimicry detector — finds processes wearing other faces |
| 8 | 🔮 **Ouija** | `ouija` | File carving & recovery — summon spirits from deleted files |
| 9 | 👻 **Eidolon** | `eidolon` | Ghost network packets — spectral traffic analysis |
| 10 | 👥 **Doppelganger** | `doppelganger` | File identity crisis detector — unmask file impostors |
| 11 | 🕯️ **Seance** | `seance` | Network necromancy — resurrect dead connections |
| 12 | 🐟 **Lamprey** | `lamprey` | Dependency infection analyzer — supply chain lamprey detection |
| 13 | 🪡 **Voodoo** | `voodoo` | Live process memory analysis — stick pins in memory |
| 14 | 🦎 **Cryptid** | `cryptid` | Hidden API & endpoint hunter — find what shouldn't be found |
| 15 | 👹 **Gremlin** | `gremlin` | Filesystem chaos agent — anomaly detection & honeypots |
| 16 | 📖 **Grimoire** | `grimoire` | The dark book of password arts — occult password generator |
| 17 | 🦌 **Wendigo** | `wendigo` | Resource devourer detector — hunt hungry processes |
| 18 | 🔔 **Harbinger** | `harbinger` | Log scream detector — the harbinger hears all |
| 19 | 🧟 **Revenant** | `revenant` | Zombie process hunter — hunt the undead |
| 20 | 📕 **Necronomicon** | `necronomicon` | System dark assessment — the book that should not be read |
| 21 | 🐉 **Chimera** | `chimera` | Binary polyglot structure validator — multi-headed file analysis |
| 22 | 🐍 **Basilisk** | `basilisk` | DNS resolver security audit — the paralyzing gaze |
| 23 | 👤 **Apparition** | `apparition` | Environment variable security audit — what lurks in your env |
| 24 | 🦂 **Manticore** | `manticore` | TLS/SSL certificate chain analyzer — the venomous sting |
| 25 | 👹 **Ghoul** | `ghoul` | Shared library injection detector — feeding on .so files |
| 26 | 💀 **Lich** | `lich` | Kernel module & rootkit surface scanner — commands the dead |
| 27 | 😈 **Imp** | `imp` | Shell history auditor — mischievous secrets finder |
| 28 | 🌑 **Shade** | `shade` | File permission anomaly hunter — lurking in the shadows |
| 29 | 🧞 **Djinn** | `djinn` | Container escape surface analyzer — trapped but scheming |
| 30 | 🦇 **Mothman** | `mothman` | Network promiscuity & ARP anomaly detector — watching from the dark |

---

## ⚡ Quick Install

```bash
# Clone the repo
git clone https://github.com/bad-antics/nullsec-freakshow.git
cd nullsec-freakshow

# Install everything (30 tools + meta-suite)
chmod +x install.sh && ./install.sh

# Or install individually
pip install -e nullsec-sigil/
pip install -e nullsec-grimoire/
```

## 🖥️ Quick Demo

```bash
# Visual hash art
sigil stamp sha256 "hello world"

# Generate an occult password
grimoire conjure --style rune --length 32

# Hunt processes pretending to be something else
skinwalker scan

# Full system dark assessment
necronomicon ritual

# DNS security audit
basilisk gaze

# Container escape surface analysis
djinn lamp

# Network anomaly detection
mothman sighting

# Shell history secrets
imp mischief

# Master suite — see all tools + install status
freakshow roster
```

## 📁 Repo Structure

```
nullsec-freakshow/          ← This repo
├── install.sh              ← One-shot installer for all 30 tools
├── nullsec-freakshow/      ← Meta-package (freakshow CLI + roster)
├── nullsec-sigil/          ← Tool 1
│   ├── sigil/
│   │   ├── __init__.py
│   │   ├── engine.py       ← Core logic
│   │   └── cli.py          ← Click CLI
│   ├── setup.py
│   └── README.md
├── nullsec-dead-drop/      ← Tool 2
├── ...                     ← Tools 3-29
└── nullsec-mothman/        ← Tool 30
```

Every tool follows the same pattern: `{name}/engine.py` (logic), `{name}/cli.py` (Click interface), `setup.py` (packaging).

## 🔧 Requirements

- Python 3.8+
- Linux (some tools read `/proc`, `/sys`, etc.)
- No external dependencies beyond `click>=8.0`

## 📄 License

MIT — [bad-antics](https://github.com/bad-antics) / nullsec 2026

---

> *The freakshow never closes. It only moves to the next town.*
