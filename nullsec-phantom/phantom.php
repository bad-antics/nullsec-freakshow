#!/usr/bin/env php
<?php
// ──────────────────────────────────────────────────────────
// 👻 nullsec-phantom — Web Shell Detector (PHP)
// Part of the nullsec freakshow suite.
//
// Scans PHP files for obfuscated web shells, backdoors,
// and suspicious code patterns.
// ──────────────────────────────────────────────────────────

define('VERSION', '1.0.0');

// ── Detection signatures ─────────────────────────────────

$SIGNATURES = [
    // Direct execution
    ['eval() call',                'CRITICAL', '/\beval\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|gzinflate|gzuncompress|str_rot13)/i'],
    ['system() with input',        'CRITICAL', '/\bsystem\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],
    ['exec() with input',          'CRITICAL', '/\bexec\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],
    ['passthru() with input',      'CRITICAL', '/\bpassthru\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],
    ['shell_exec() with input',    'CRITICAL', '/\bshell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],
    ['popen() with input',         'CRITICAL', '/\bpopen\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],
    ['proc_open() call',           'HIGH',     '/\bproc_open\s*\(/i'],
    ['pcntl_exec() call',          'CRITICAL', '/\bpcntl_exec\s*\(/i'],
    ['backtick execution',         'HIGH',     '/`\s*\$_(?:GET|POST|REQUEST|COOKIE)/'],

    // Obfuscation
    ['base64_decode + eval',       'CRITICAL', '/eval\s*\(\s*base64_decode/i'],
    ['gzinflate + base64',         'CRITICAL', '/gzinflate\s*\(\s*base64_decode/i'],
    ['str_rot13 + eval',           'CRITICAL', '/eval\s*\(\s*str_rot13/i'],
    ['chr() obfuscation chain',    'HIGH',     '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i'],
    ['hex2bin obfuscation',        'HIGH',     '/eval\s*\(\s*hex2bin/i'],
    ['\\x hex escapes (long)',     'MEDIUM',   '/(?:\\\\x[0-9a-f]{2}){10,}/i'],
    ['Long base64 blob',          'MEDIUM',   '/[A-Za-z0-9+\/]{100,}={0,2}/'],
    ['Dynamic function call',      'HIGH',     '/\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST)/i'],

    // File operations
    ['file_put_contents + input',  'HIGH',     '/file_put_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)/i'],
    ['fwrite with superglobal',    'HIGH',     '/fwrite\s*\([^)]*\$_(?:GET|POST|REQUEST)/i'],
    ['move_uploaded_file unchecked','MEDIUM',   '/move_uploaded_file\s*\(\s*\$_FILES/i'],

    // Networking
    ['fsockopen()',                'MEDIUM',    '/\bfsockopen\s*\(/i'],
    ['curl_exec with input',      'HIGH',      '/curl_exec\s*\(.*\$_(?:GET|POST|REQUEST)/i'],
    ['Reverse shell pattern',     'CRITICAL',  '/fsockopen\s*\([^)]+\)\s*.*(?:fwrite|fputs|stream_copy)/is'],

    // Stealth / persistence
    ['@error suppression + exec', 'HIGH',      '/@\s*(?:eval|system|exec|passthru|shell_exec)\s*\(/i'],
    ['ini_set disable_functions', 'CRITICAL',  '/ini_set\s*\(\s*[\'"]disable_functions[\'"]/i'],
    ['preg_replace /e modifier',  'CRITICAL',  '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i'],
    ['assert() as eval',          'HIGH',      '/\bassert\s*\(\s*(?:\$_|base64_decode|str_rot13)/i'],
    ['create_function()',         'HIGH',      '/\bcreate_function\s*\(/i'],
    ['ReflectionFunction',        'MEDIUM',    '/new\s+ReflectionFunction\s*\(\s*\$/i'],

    // Known webshell signatures
    ['WSO / FilesMan signature',  'CRITICAL',  '/(?:WSO|FilesMan|b374k|c99|r57|c100|Locus7s)/i'],
    ['PHP backdoor marker',       'CRITICAL',  '/(?:phpspy|spy[_-]?shell|web[_-]?shell|backdoor)/i'],
    ['Hidden iframe/script',      'HIGH',      '/<\s*iframe[^>]+style\s*=\s*[\'"][^"]*display\s*:\s*none/i'],
];

// ── Scan engine ──────────────────────────────────────────

class Finding {
    public string $file;
    public int    $line;
    public string $name;
    public string $severity;
    public string $match;

    public function __construct(string $file, int $line, string $name, string $severity, string $match) {
        $this->file = $file;
        $this->line = $line;
        $this->name = $name;
        $this->severity = $severity;
        $this->match = $match;
    }
}

function scan_file(string $path, array $signatures): array {
    $content = @file_get_contents($path);
    if ($content === false) return [];

    $lines = explode("\n", $content);
    $findings = [];

    foreach ($lines as $idx => $line) {
        foreach ($signatures as [$name, $severity, $pattern]) {
            if (preg_match($pattern, $line, $m)) {
                $match = mb_substr(trim($m[0]), 0, 80);
                $findings[] = new Finding($path, $idx + 1, $name, $severity, $match);
            }
        }
    }

    // Check entropy (high entropy = likely encoded payload)
    $non_ws = preg_replace('/\s/', '', $content);
    if (strlen($non_ws) > 500) {
        $entropy = calculate_entropy($non_ws);
        if ($entropy > 5.5) {
            $findings[] = new Finding($path, 0, "High entropy file ($entropy)", "MEDIUM", "possible encoded payload");
        }
    }

    return $findings;
}

function calculate_entropy(string $data): float {
    $freq = [];
    $len = strlen($data);
    for ($i = 0; $i < $len; $i++) {
        $c = $data[$i];
        $freq[$c] = ($freq[$c] ?? 0) + 1;
    }
    $entropy = 0.0;
    foreach ($freq as $count) {
        $p = $count / $len;
        if ($p > 0) $entropy -= $p * log($p, 2);
    }
    return round($entropy, 2);
}

function scan_directory(string $dir, array $signatures): array {
    $findings = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    $count = 0;
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $ext = strtolower($file->getExtension());
        // Scan PHP and related files
        if (!in_array($ext, ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'inc', 'module'])) continue;

        $count++;
        $results = scan_file($file->getPathname(), $signatures);
        $findings = array_merge($findings, $results);

        if (posix_isatty(STDERR)) {
            fwrite(STDERR, "\r  Scanning... $count files");
        }
    }

    if (posix_isatty(STDERR)) {
        fwrite(STDERR, "\r  Scanning... $count files done!\n");
    }

    return [$findings, $count];
}

// ── Display ──────────────────────────────────────────────

function sev_icon(string $sev): string {
    return match($sev) {
        'CRITICAL' => '🔴',
        'HIGH'     => '🟡',
        'MEDIUM'   => '🔵',
        default    => '⚪',
    };
}

function sev_color(string $sev): string {
    return match($sev) {
        'CRITICAL' => "\033[0;31m",
        'HIGH'     => "\033[0;33m",
        'MEDIUM'   => "\033[0;36m",
        default    => "\033[0m",
    };
}

$NC = "\033[0m";

// ── Commands ─────────────────────────────────────────────

function cmd_scan(string $target, array $signatures): void {
    global $NC;

    echo "\n👻  PHANTOM — Web Shell Detector\n";
    echo "═══════════════════════════════════════\n";
    echo "  Target: $target\n";

    if (is_file($target)) {
        $findings = scan_file($target, $signatures);
        $file_count = 1;
    } elseif (is_dir($target)) {
        [$findings, $file_count] = scan_directory($target, $signatures);
    } else {
        fwrite(STDERR, "  ❌ Not found: $target\n");
        exit(1);
    }

    echo "  Files scanned: $file_count\n";
    echo "  ─────────────────────────────────────\n";

    if (empty($findings)) {
        echo "\n  ✅ No web shells detected\n\n";
        return;
    }

    // Sort by severity
    $sev_order = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2];
    usort($findings, function($a, $b) use ($sev_order) {
        return ($sev_order[$a->severity] ?? 9) <=> ($sev_order[$b->severity] ?? 9);
    });

    echo "\n  🚨 " . count($findings) . " suspicious patterns found:\n\n";

    foreach ($findings as $f) {
        $icon = sev_icon($f->severity);
        $col = sev_color($f->severity);
        echo "    $icon {$col}[{$f->severity}]{$NC} {$f->name}\n";
        echo "      File: {$f->file}:{$f->line}\n";
        echo "      Code: {$f->match}\n\n";
    }

    // Summary
    $by_sev = [];
    foreach ($findings as $f) {
        $by_sev[$f->severity] = ($by_sev[$f->severity] ?? 0) + 1;
    }

    echo "  ─────────────────────────────────────\n";
    $crit = $by_sev['CRITICAL'] ?? 0;
    $high = $by_sev['HIGH'] ?? 0;
    $med  = $by_sev['MEDIUM'] ?? 0;
    echo "  CRITICAL: $crit  |  HIGH: $high  |  MEDIUM: $med\n\n";
}

function print_help(): void {
    echo <<<HELP

👻  nullsec-phantom v1.0.0 — Web Shell Detector (PHP)
   Part of the nullsec freakshow suite.

Usage:
  phantom scan <dir|file>    Scan for web shells
  phantom --help             This help

Detects:
  • eval/system/exec with user input (\$_GET, \$_POST, \$_REQUEST)
  • Obfuscation: base64_decode, gzinflate, str_rot13, hex2bin, chr() chains
  • File operations with superglobals
  • Reverse shell patterns (fsockopen + fwrite)
  • Known webshell signatures (WSO, c99, r57, b374k, etc.)
  • High-entropy encoded payloads
  • 30+ detection signatures


HELP;
}

// ── CLI ──────────────────────────────────────────────────

$cmd = $argv[1] ?? '--help';

switch ($cmd) {
    case 'scan':
        $target = $argv[2] ?? '.';
        cmd_scan($target, $SIGNATURES);
        break;
    case '--help':
    case '-h':
        print_help();
        break;
    default:
        print_help();
}
