# 👻 nullsec-phantom

**Web Shell Detector** — PHP

Part of the **nullsec freakshow** suite.

## What It Does

Phantom scans PHP files for obfuscated web shells, backdoors, and suspicious code:

- **30+ detection signatures** covering eval/exec injection, obfuscation chains, file ops, networking, stealth techniques
- **Known webshell detection** — WSO, FilesMan, b374k, c99, r57, c100, Locus7s, phpspy
- **Entropy analysis** — detects encoded payloads via Shannon entropy
- **Multi-extension** — scans .php, .php3-7, .phtml, .phar, .inc, .module
- **Severity classification** — CRITICAL, HIGH, MEDIUM

## Usage

```bash
phantom scan /var/www/html            # Scan web directory
phantom scan /var/www/html/shell.php  # Scan single file
phantom --help                        # Help
```

## Detection Categories

| Category | Examples |
|----------|---------|
| Code execution | eval(), system(), exec(), passthru(), shell_exec(), popen() |
| Obfuscation | base64_decode, gzinflate, str_rot13, hex2bin, chr() chains |
| File operations | file_put_contents, fwrite with user input |
| Networking | fsockopen, reverse shell patterns |
| Stealth | @error suppression, preg_replace /e, ini_set disable_functions |
| Known shells | WSO, c99, r57, b374k, FilesMan, phpspy |

## Install

```bash
chmod +x phantom.php
sudo ln -sf $(pwd)/phantom.php /usr/local/bin/phantom
```

## Language

PHP 8.x CLI — no Composer dependencies.

## License

MIT — bad-antics / nullsec
