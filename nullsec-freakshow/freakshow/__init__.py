"""
🎪 nullsec-freakshow — The Freakshow Suite
40 weird & creepy security tools by bad-antics.
"""
__version__ = "3.0.0"
__author__ = "bad-antics"

TOOLS = [
    # ── Original 20 (Python) ──
    {"name": "sigil",        "package": "nullsec-sigil",        "emoji": "🔮", "lang": "Python", "desc": "Visual hash fingerprinting"},
    {"name": "dead-drop",    "package": "nullsec-dead-drop",    "emoji": "📦", "lang": "Python", "desc": "LSB steganography"},
    {"name": "miasma",       "package": "nullsec-miasma",       "emoji": "��", "lang": "Python", "desc": "Shannon entropy analyzer"},
    {"name": "temporal",     "package": "nullsec-temporal",     "emoji": "⏰", "lang": "Python", "desc": "Forensic timestamp analyzer"},
    {"name": "hexspeak",     "package": "nullsec-hexspeak",     "emoji": "🔢", "lang": "Python", "desc": "Hex word encoder/decoder"},
    {"name": "whisper",      "package": "nullsec-whisper",      "emoji": "👁️", "lang": "Python", "desc": "Spectral audio steganography"},
    {"name": "skinwalker",   "package": "nullsec-skinwalker",   "emoji": "🐺", "lang": "Python", "desc": "Process mimicry detector"},
    {"name": "ouija",        "package": "nullsec-ouija",        "emoji": "🔮", "lang": "Python", "desc": "File carving & recovery"},
    {"name": "eidolon",      "package": "nullsec-eidolon",      "emoji": "👻", "lang": "Python", "desc": "Ghost network packets"},
    {"name": "doppelganger", "package": "nullsec-doppelganger", "emoji": "👥", "lang": "Python", "desc": "File identity crisis detector"},
    {"name": "seance",       "package": "nullsec-seance",       "emoji": "🕯️", "lang": "Python", "desc": "Network necromancy"},
    {"name": "lamprey",      "package": "nullsec-lamprey",      "emoji": "🐟", "lang": "Python", "desc": "Dependency infection analyzer"},
    {"name": "voodoo",       "package": "nullsec-voodoo",       "emoji": "🪡", "lang": "Python", "desc": "Live process memory analysis"},
    {"name": "cryptid",      "package": "nullsec-cryptid",      "emoji": "🦎", "lang": "Python", "desc": "Hidden API & endpoint hunter"},
    {"name": "gremlin",      "package": "nullsec-gremlin",      "emoji": "👹", "lang": "Python", "desc": "Filesystem chaos agent"},
    {"name": "grimoire",     "package": "nullsec-grimoire",     "emoji": "📖", "lang": "Python", "desc": "Occult password generator"},
    {"name": "wendigo",      "package": "nullsec-wendigo",      "emoji": "🦌", "lang": "Python", "desc": "Resource devourer detector"},
    {"name": "harbinger",    "package": "nullsec-harbinger",    "emoji": "🔔", "lang": "Python", "desc": "Log scream detector"},
    {"name": "revenant",     "package": "nullsec-revenant",     "emoji": "🧟", "lang": "Python", "desc": "Zombie process hunter"},
    {"name": "necronomicon", "package": "nullsec-necronomicon", "emoji": "📕", "lang": "Python", "desc": "System dark assessment"},
    # ── Wave 2: 10 more Python ──
    {"name": "chimera",     "package": "nullsec-chimera",     "emoji": "🐉", "lang": "Python", "desc": "Binary polyglot structure validator"},
    {"name": "basilisk",    "package": "nullsec-basilisk",    "emoji": "🐍", "lang": "Python", "desc": "DNS resolver security audit"},
    {"name": "apparition",  "package": "nullsec-apparition",  "emoji": "👤", "lang": "Python", "desc": "Environment variable security audit"},
    {"name": "manticore",   "package": "nullsec-manticore",   "emoji": "🦂", "lang": "Python", "desc": "TLS/SSL certificate chain analyzer"},
    {"name": "ghoul",       "package": "nullsec-ghoul",       "emoji": "👹", "lang": "Python", "desc": "Shared library injection detector"},
    {"name": "lich",        "package": "nullsec-lich",        "emoji": "💀", "lang": "Python", "desc": "Kernel module & rootkit scanner"},
    {"name": "imp",         "package": "nullsec-imp",         "emoji": "😈", "lang": "Python", "desc": "Shell history auditor"},
    {"name": "shade",       "package": "nullsec-shade",       "emoji": "🌑", "lang": "Python", "desc": "File permission anomaly hunter"},
    {"name": "djinn",       "package": "nullsec-djinn",       "emoji": "🧞", "lang": "Python", "desc": "Container escape surface analyzer"},
    {"name": "mothman",     "package": "nullsec-mothman",     "emoji": "🦇", "lang": "Python", "desc": "Network promiscuity & ARP detector"},
    # ── Wave 3: 10 multi-language ──
    {"name": "wraith",      "package": "nullsec-wraith",      "emoji": "👻", "lang": "Go",     "desc": "Ephemeral port scanner"},
    {"name": "banshee",     "package": "nullsec-banshee",     "emoji": "💀", "lang": "Rust",   "desc": "File integrity screamer"},
    {"name": "poltergeist", "package": "nullsec-poltergeist", "emoji": "👻", "lang": "C",      "desc": "/proc anomaly detector"},
    {"name": "kobold",      "package": "nullsec-kobold",      "emoji": "🔧", "lang": "Node.js","desc": "HTTP header security auditor"},
    {"name": "specter",     "package": "nullsec-specter",     "emoji": "👁️", "lang": "Bash",   "desc": "SSH config & key auditor"},
    {"name": "changeling",  "package": "nullsec-changeling",  "emoji": "🎭", "lang": "Ruby",   "desc": "Git repository secrets scanner"},
    {"name": "familiar",    "package": "nullsec-familiar",    "emoji": "🐈", "lang": "Perl",   "desc": "Log pattern extractor"},
    {"name": "golem",       "package": "nullsec-golem",       "emoji": "🗿", "lang": "C++",    "desc": "Memory-mapped file hasher"},
    {"name": "phantom",     "package": "nullsec-phantom",     "emoji": "👻", "lang": "PHP",    "desc": "Web shell detector"},
    {"name": "yokai",       "package": "nullsec-yokai",       "emoji": "🏮", "lang": "Python", "desc": "Cron & systemd timer auditor"},
]

__all__ = ["TOOLS"]
