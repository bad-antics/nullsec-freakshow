#!/usr/bin/env ruby
# frozen_string_literal: true

# ──────────────────────────────────────────────────────────
# 🎭 nullsec-changeling — Git Repository Secrets Scanner (Ruby)
# Part of the nullsec freakshow suite.
#
# Scans git commit history for leaked secrets: API keys,
# passwords, private keys, tokens, and credentials.
# ──────────────────────────────────────────────────────────

VERSION = "1.0.0"

# Secret detection patterns — [name, severity, regex]
SECRET_PATTERNS = [
  ["AWS Access Key",        "CRITICAL", /AKIA[0-9A-Z]{16}/],
  ["AWS Secret Key",        "CRITICAL", /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{40})['"]?/i],
  ["GitHub Token",          "CRITICAL", /gh[ps]_[A-Za-z0-9_]{36,}/],
  ["GitHub OAuth",          "CRITICAL", /gho_[A-Za-z0-9_]{36,}/],
  ["Generic API Key",       "HIGH",     /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9\-_.]{20,})['"]?/i],
  ["Generic Secret",        "HIGH",     /(?:secret|password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"](?:\s|$|,|;)/i],
  ["Private Key",           "CRITICAL", /-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----/],
  ["Slack Token",           "CRITICAL", /xox[bpras]-[A-Za-z0-9\-]{10,}/],
  ["Slack Webhook",         "HIGH",     /hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/],
  ["Google API Key",        "HIGH",     /AIza[0-9A-Za-z\-_]{35}/],
  ["Heroku API Key",        "HIGH",     /[hH]eroku.*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/],
  ["JWT Token",             "MEDIUM",   /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["Stripe Key",            "CRITICAL", /[sr]k_(live|test)_[A-Za-z0-9]{20,}/],
  ["Twilio API Key",        "HIGH",     /SK[0-9a-fA-F]{32}/],
  ["SendGrid Key",          "CRITICAL", /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/],
  ["Database URL",          "CRITICAL", /(?:mysql|postgres|mongodb|redis):\/\/[^:]+:[^@]+@[^\s'"]+/i],
  ["SSH URL w/ Password",   "HIGH",     /ssh:\/\/[^:]+:[^@]+@/i],
  ["Base64 Password",       "MEDIUM",   /(?:password|passwd|pwd)\s*[:=]\s*['"]?(?:[A-Za-z0-9+\/]{20,}={0,2})['"]?/i],
  [".env Assignment",       "MEDIUM",   /^[A-Z_]{3,}=(?:['"])?(?:sk_|pk_|key_|secret_|password|token)/i],
  ["IP + Credentials",      "HIGH",     /https?:\/\/[^:]+:[^@]+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/],
]

# Files that should never be committed
DANGEROUS_FILES = [
  [".env",              "HIGH",     /^\.env(?:\.\w+)?$/],
  ["Private Key File",  "CRITICAL", /^.*\.pem$/],
  ["PKCS12 Keystore",   "CRITICAL", /^.*\.p12$/],
  ["Java Keystore",     "HIGH",     /^.*\.jks$/],
  ["KeePass DB",        "CRITICAL", /^.*\.kdbx?$/],
  ["SQLite DB",         "MEDIUM",   /^.*\.sqlite3?$/],
  ["htpasswd",          "HIGH",     /\.htpasswd$/],
  ["Credentials File",  "HIGH",     /credentials(?:\.\w+)?$/i],
  ["Shadow File",       "CRITICAL", /^shadow$/],
  ["id_rsa / id_ed25519","CRITICAL", /^id_(?:rsa|dsa|ecdsa|ed25519)$/],
]

class Finding
  attr_reader :commit, :author, :date, :file, :line, :pattern_name, :severity, :match

  def initialize(commit:, author:, date:, file:, line:, pattern_name:, severity:, match:)
    @commit = commit
    @author = author
    @date = date
    @file = file
    @line = line
    @pattern_name = pattern_name
    @severity = severity
    @match = match
  end
end

def color(sev)
  case sev
  when "CRITICAL" then "\033[0;31m"
  when "HIGH"     then "\033[0;33m"
  when "MEDIUM"   then "\033[0;36m"
  else "\033[0;37m"
  end
end

def nc
  "\033[0m"
end

def icon(sev)
  case sev
  when "CRITICAL" then "🔴"
  when "HIGH"     then "🟡"
  when "MEDIUM"   then "🔵"
  else "⚪"
  end
end

def scan_diff(diff_text, commit, author, date)
  findings = []
  current_file = nil

  diff_text.each_line do |line|
    if line.start_with?("diff --git")
      current_file = line.match(%r{b/(.+)$})&.[](1)
      next
    end

    next unless line.start_with?("+") && !line.start_with?("+++")
    next if current_file.nil?

    content = line[1..]  # strip leading '+'

    SECRET_PATTERNS.each do |name, sev, pattern|
      next unless content.match?(pattern)
      matched = content.match(pattern).to_s
      # Redact the match for display
      redacted = matched.length > 12 ? matched[0..5] + "***" + matched[-4..] : "***"
      findings << Finding.new(
        commit: commit, author: author, date: date,
        file: current_file, line: content.strip[0..80],
        pattern_name: name, severity: sev, match: redacted
      )
    end
  end

  findings
end

def scan_filenames(files_text, commit, author, date)
  findings = []
  files_text.each_line do |fname|
    fname = fname.strip
    basename = File.basename(fname)
    DANGEROUS_FILES.each do |name, sev, pattern|
      next unless basename.match?(pattern)
      findings << Finding.new(
        commit: commit, author: author, date: date,
        file: fname, line: "(dangerous file committed)",
        pattern_name: name, severity: sev, match: basename
      )
    end
  end
  findings
end

def cmd_scan(path, max_commits: nil, branch: nil)
  unless File.directory?(File.join(path, ".git"))
    STDERR.puts "  ❌ Not a git repository: #{path}"
    exit 1
  end

  puts
  puts "🎭  CHANGELING — Git Secrets Scanner"
  puts "═══════════════════════════════════════"
  puts "  Target: #{path}"

  # Build git log command
  log_cmd = "git -C '#{path}' log --all --format='%H|%an|%ai' --diff-filter=ACMR"
  log_cmd += " -n #{max_commits}" if max_commits
  log_cmd += " #{branch}" if branch

  commits = `#{log_cmd}`.strip.split("\n").reject(&:empty?)
  total = commits.size
  puts "  Commits to scan: #{total}"
  puts "  ─────────────────────────────────────"

  all_findings = []
  scanned = 0

  commits.each do |entry|
    parts = entry.split("|", 3)
    next if parts.size < 3
    sha, author, date = parts
    sha = sha.strip

    # Get diff for this commit
    diff = `git -C '#{path}' diff-tree -p #{sha} 2>/dev/null`
    all_findings.concat(scan_diff(diff, sha[0..7], author, date))

    # Get file list
    files = `git -C '#{path}' diff-tree --no-commit-id --name-only -r #{sha} 2>/dev/null`
    all_findings.concat(scan_filenames(files, sha[0..7], author, date))

    scanned += 1
    STDERR.print "\r  Scanning... #{scanned}/#{total}" if STDERR.tty?
  end
  STDERR.puts "\r  Scanning... done!          " if STDERR.tty?

  # Deduplicate
  seen = {}
  unique = all_findings.reject do |f|
    key = "#{f.commit}:#{f.file}:#{f.pattern_name}"
    if seen[key]
      true
    else
      seen[key] = true
      false
    end
  end

  # Sort by severity
  sev_order = { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2 }
  unique.sort_by! { |f| [sev_order[f.severity] || 9, f.date] }

  # Print findings
  if unique.empty?
    puts "\n  ✅ No secrets found in #{scanned} commits\n\n"
    return
  end

  puts "\n  🚨 #{unique.size} secrets found:\n"

  unique.each do |f|
    puts "    #{icon(f.severity)} #{color(f.severity)}[#{f.severity}]#{nc} #{f.pattern_name}"
    puts "      Commit: #{f.commit} (#{f.author}, #{f.date})"
    puts "      File:   #{f.file}"
    puts "      Match:  #{f.match}"
    puts
  end

  # Summary
  by_sev = unique.group_by(&:severity)
  puts "  ─────────────────────────────────────"
  crit = (by_sev["CRITICAL"] || []).size
  high = (by_sev["HIGH"] || []).size
  med  = (by_sev["MEDIUM"] || []).size
  puts "  #{crit > 0 ? "\033[0;31m" : ""}CRITICAL: #{crit}#{nc}  |  HIGH: #{high}  |  MEDIUM: #{med}"
  puts "  Scanned #{scanned} commits\n\n"
end

def print_help
  puts <<~HELP

    🎭  nullsec-changeling v#{VERSION} — Git Secrets Scanner (Ruby)
       Part of the nullsec freakshow suite.

    Usage:
      changeling scan [path]            Scan git repo (default: cwd)
      changeling scan [path] -n 100     Scan last 100 commits
      changeling --help                 This help

    Detects:
      • AWS keys, GitHub tokens, Slack tokens
      • API keys, passwords, secrets in code
      • Private keys, database URLs
      • Stripe, SendGrid, Twilio keys
      • Dangerous files (.env, .pem, id_rsa, etc.)

  HELP
end

# ── CLI ──────────────────────────────────────────────────
case ARGV[0]
when "scan"
  path = ARGV[1] || Dir.pwd
  max_commits = nil
  if (idx = ARGV.index("-n"))
    max_commits = ARGV[idx + 1]&.to_i
  end
  cmd_scan(path, max_commits: max_commits)
when "--help", "-h"
  print_help
else
  print_help
end
