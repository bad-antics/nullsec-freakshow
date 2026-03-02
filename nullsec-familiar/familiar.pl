#!/usr/bin/env perl
# ──────────────────────────────────────────────────────────
# 🐈 nullsec-familiar — Log Pattern Extractor (Perl)
# Part of the nullsec freakshow suite.
#
# Regex-heavy log mining. Extracts IPs, emails, URLs,
# error patterns, credentials, and suspicious entries.
# ──────────────────────────────────────────────────────────
use strict;
use warnings;
use File::Find;
use Getopt::Long;

my $VERSION = "1.0.0";

# ── Pattern definitions ──────────────────────────────────
my %PATTERNS = (
    ipv4    => qr/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
    ipv6    => qr/\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b/,
    email   => qr/\b([a-zA-Z0-9._%+\-]+\@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/,
    url     => qr{(https?://[^\s'"<>\)]+)},
    mac     => qr/\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b/,
    path    => qr{(/(?:etc|var|tmp|home|usr|opt|root)/[^\s:'"]+)},
    error   => qr/((?:error|fail(?:ed|ure)?|exception|critical|panic|fatal|denied|refused|timeout|unauthorized|forbidden)[\s:].{0,120})/i,
    cred    => qr/((?:password|passwd|pwd|token|secret|key|credential|auth)[\s]*[=:]\s*\S+)/i,
    port    => qr/\b(?:port|listening on|:)[\s]*(\d{2,5})\b/i,
    user    => qr/(?:user(?:name)?|login|uid|account)[\s]*[=:]\s*['"]?([a-zA-Z0-9._\-]+)/i,
);

my %SEVERITY = (
    cred  => "CRITICAL",
    error => "HIGH",
    email => "MEDIUM",
    url   => "MEDIUM",
    ipv4  => "LOW",
    ipv6  => "LOW",
    mac   => "LOW",
    path  => "LOW",
    port  => "LOW",
    user  => "MEDIUM",
);

# ── Colors ───────────────────────────────────────────────
my $RED = "\033[0;31m";
my $YEL = "\033[0;33m";
my $GRN = "\033[0;32m";
my $CYN = "\033[0;36m";
my $NC  = "\033[0m";

sub sev_color {
    my $s = shift;
    return $RED if $s eq "CRITICAL";
    return $YEL if $s eq "HIGH";
    return $CYN if $s eq "MEDIUM";
    return $NC;
}

sub sev_icon {
    my $s = shift;
    return "🔴" if $s eq "CRITICAL";
    return "🟡" if $s eq "HIGH";
    return "🔵" if $s eq "MEDIUM";
    return "⚪";
}

# ── Extraction engine ────────────────────────────────────
sub extract_from_file {
    my ($file, $types, $results) = @_;

    open(my $fh, '<', $file) or do {
        warn "  ⚠️  Cannot open $file: $!\n";
        return;
    };

    my $lineno = 0;
    while (my $line = <$fh>) {
        $lineno++;
        chomp $line;

        for my $type (@$types) {
            my $pat = $PATTERNS{$type};
            while ($line =~ /$pat/g) {
                my $match = $1;
                next unless defined $match && length($match) > 2;

                # Skip private IPs if they're common
                if ($type eq 'ipv4') {
                    next if $match eq '127.0.0.1' || $match eq '0.0.0.0';
                    # Validate octets
                    my @octets = split /\./, $match;
                    my $valid = 1;
                    for my $o (@octets) {
                        $valid = 0 if $o > 255;
                    }
                    next unless $valid;
                }

                # Skip common ports
                if ($type eq 'port') {
                    next unless $match >= 1 && $match <= 65535;
                }

                $results->{$type}{$match} //= [];
                push @{$results->{$type}{$match}}, {
                    file   => $file,
                    line   => $lineno,
                    sample => substr($line, 0, 120),
                };
            }
        }
    }
    close $fh;
}

# ── Commands ─────────────────────────────────────────────
sub cmd_extract {
    my ($paths, $types, $top_n) = @_;

    print "\n🐈  FAMILIAR — Log Pattern Extractor\n";
    print "═══════════════════════════════════════\n";
    print "  Targets: " . join(", ", @$paths) . "\n";
    print "  Types:   " . join(", ", @$types) . "\n";

    my %results;
    my $file_count = 0;

    for my $path (@$paths) {
        if (-f $path) {
            extract_from_file($path, $types, \%results);
            $file_count++;
        } elsif (-d $path) {
            find(sub {
                return unless -f && -T;  # text files only
                return if $File::Find::name =~ /\.(gz|bz2|xz|zip|tar|bin|so|png|jpg)$/;
                extract_from_file($File::Find::name, $types, \%results);
                $file_count++;
            }, $path);
        } else {
            warn "  ⚠️  Not found: $path\n";
        }
    }

    print "  Files scanned: $file_count\n";
    print "  ─────────────────────────────────────\n";

    my $total_findings = 0;

    # Sort types by severity
    my %sev_order = (CRITICAL => 0, HIGH => 1, MEDIUM => 2, LOW => 3);
    my @sorted_types = sort {
        ($sev_order{$SEVERITY{$a}} // 9) <=> ($sev_order{$SEVERITY{$b}} // 9)
    } @$types;

    for my $type (@sorted_types) {
        next unless exists $results{$type};
        my $data = $results{$type};
        my $sev = $SEVERITY{$type} // "LOW";
        my $count = scalar keys %$data;
        $total_findings += $count;

        print "\n  " . sev_icon($sev) . " " . sev_color($sev) . uc($type) . "$NC ($count unique)\n";

        # Sort by occurrence count, take top N
        my @sorted = sort { scalar(@{$data->{$b}}) <=> scalar(@{$data->{$a}}) } keys %$data;
        @sorted = splice(@sorted, 0, $top_n) if $top_n;

        for my $match (@sorted) {
            my $occurrences = scalar @{$data->{$match}};
            my $first = $data->{$match}[0];
            printf("    %-40s  (%d occurrences)\n", $match, $occurrences);
            printf("      └─ %s:%d\n", $first->{file}, $first->{line}) if $occurrences <= 3;
        }
    }

    print "\n  ─────────────────────────────────────\n";
    print "  Total: $total_findings unique findings from $file_count files\n\n";
}

sub cmd_summary {
    my ($paths) = @_;
    my @all_types = keys %PATTERNS;

    print "\n🐈  FAMILIAR — Quick Summary\n";
    print "═══════════════════════════════════════\n";

    my %results;
    my $file_count = 0;

    for my $path (@$paths) {
        if (-f $path) {
            extract_from_file($path, \@all_types, \%results);
            $file_count++;
        } elsif (-d $path) {
            find(sub {
                return unless -f && -T;
                return if $File::Find::name =~ /\.(gz|bz2|xz|zip|tar|bin|so|png|jpg)$/;
                extract_from_file($File::Find::name, \@all_types, \%results);
                $file_count++;
            }, $path);
        }
    }

    print "  Files: $file_count\n\n";

    my %sev_order = (CRITICAL => 0, HIGH => 1, MEDIUM => 2, LOW => 3);
    my @sorted = sort { ($sev_order{$SEVERITY{$a}} // 9) <=> ($sev_order{$SEVERITY{$b}} // 9) } keys %PATTERNS;

    for my $type (@sorted) {
        my $count = exists $results{$type} ? scalar(keys %{$results{$type}}) : 0;
        my $sev = $SEVERITY{$type} // "LOW";
        printf("    %s %-12s %s%-8s%s  %d unique\n", sev_icon($sev), uc($type), sev_color($sev), $sev, $NC, $count);
    }

    print "\n";
}

# ── Help ─────────────────────────────────────────────────
sub print_help {
    print <<HELP;

🐈  nullsec-familiar v$VERSION — Log Pattern Extractor (Perl)
   Part of the nullsec freakshow suite.

Usage:
  familiar extract <file|dir> [--type ipv4,email,url] [--top 20]
  familiar summary <file|dir>
  familiar --help

Types: ipv4, ipv6, email, url, mac, path, error, cred, port, user

Examples:
  familiar extract /var/log/syslog --type ipv4,error
  familiar extract /var/log/ --top 10
  familiar summary /var/log/auth.log

HELP
}

# ── CLI ──────────────────────────────────────────────────
my $cmd = shift @ARGV // "--help";

if ($cmd eq "extract") {
    my @types_filter;
    my $top_n = 0;
    my $types_str;

    GetOptions(
        "type=s" => \$types_str,
        "top=i"  => \$top_n,
    );

    my @paths = @ARGV;
    @paths = (".") unless @paths;

    if ($types_str) {
        @types_filter = split /,/, $types_str;
    } else {
        @types_filter = keys %PATTERNS;
    }

    cmd_extract(\@paths, \@types_filter, $top_n || undef);

} elsif ($cmd eq "summary") {
    my @paths = @ARGV;
    @paths = (".") unless @paths;
    cmd_summary(\@paths);

} elsif ($cmd eq "--help" || $cmd eq "-h") {
    print_help();
} else {
    print_help();
}
