#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
# 👁️ nullsec-specter — SSH Config & Key Auditor (Bash)
# Part of the nullsec freakshow suite.
#
# Audits sshd_config, SSH keys, authorized_keys, and
# known_hosts for security weaknesses.
# ──────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
NC='\033[0m'
ISSUES=0
WARNINGS=0

pass()  { echo -e "    ${GRN}✅${NC} $*"; }
warn()  { echo -e "    ${YEL}🟡${NC} [$1] $2"; ((WARNINGS++)); }
fail()  { echo -e "    ${RED}🔴${NC} [$1] $2"; ((ISSUES++)); }

audit_sshd_config() {
    echo -e "\n  🔒 SSHD Configuration"
    echo    "  ─────────────────────────────────────"

    local conf=""
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] && conf="$conf $f"
    done

    if [[ -z "$conf" ]]; then
        warn "MEDIUM" "No sshd_config found"
        return
    fi

    # PermitRootLogin
    local root_login
    root_login=$(grep -hi "^PermitRootLogin" $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$root_login" == "yes" ]]; then
        fail "CRITICAL" "PermitRootLogin yes — root can SSH directly"
    elif [[ "$root_login" == "prohibit-password" || "$root_login" == "without-password" ]]; then
        warn "MEDIUM" "PermitRootLogin $root_login — key-only root (consider 'no')"
    elif [[ "$root_login" == "no" ]]; then
        pass "PermitRootLogin no"
    else
        warn "MEDIUM" "PermitRootLogin not explicitly set (default varies)"
    fi

    # PasswordAuthentication
    local pass_auth
    pass_auth=$(grep -hi "^PasswordAuthentication" $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$pass_auth" == "yes" ]]; then
        warn "HIGH" "PasswordAuthentication yes — brute-force possible"
    elif [[ "$pass_auth" == "no" ]]; then
        pass "PasswordAuthentication no (key-only)"
    else
        warn "MEDIUM" "PasswordAuthentication not explicitly set"
    fi

    # Port
    local port
    port=$(grep -hi "^Port " $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$port" == "22" || -z "$port" ]]; then
        warn "LOW" "SSH on default port 22"
    else
        pass "SSH on non-standard port $port"
    fi

    # Protocol version
    local proto
    proto=$(grep -hi "^Protocol " $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$proto" == "1" ]]; then
        fail "CRITICAL" "Protocol 1 enabled — insecure!"
    fi

    # X11 forwarding
    local x11
    x11=$(grep -hi "^X11Forwarding" $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$x11" == "yes" ]]; then
        warn "LOW" "X11Forwarding enabled"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(grep -hi "^MaxAuthTries" $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ -n "$max_auth" && "$max_auth" -gt 6 ]]; then
        warn "MEDIUM" "MaxAuthTries=$max_auth (high — brute force risk)"
    elif [[ -n "$max_auth" ]]; then
        pass "MaxAuthTries=$max_auth"
    fi

    # AllowAgentForwarding
    local agent_fwd
    agent_fwd=$(grep -hi "^AllowAgentForwarding" $conf 2>/dev/null | tail -1 | awk '{print $2}') || true
    if [[ "$agent_fwd" == "yes" || -z "$agent_fwd" ]]; then
        warn "LOW" "Agent forwarding enabled (lateral movement risk)"
    fi
}

audit_ssh_keys() {
    echo -e "\n  🔑 SSH Key Audit"
    echo    "  ─────────────────────────────────────"

    local key_count=0

    # Check user keys
    for home_dir in /home/* /root; do
        [[ -d "$home_dir/.ssh" ]] || continue
        local user
        user=$(basename "$home_dir")

        for key in "$home_dir"/.ssh/id_*; do
            [[ -f "$key" ]] || continue
            [[ "$key" == *.pub ]] && continue
            ((key_count++))

            # Check key permissions
            local perms
            perms=$(stat -c '%a' "$key" 2>/dev/null) || continue
            if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                fail "HIGH" "$key has permissions $perms (should be 600)"
            fi

            # Check key type and strength
            local key_info
            key_info=$(ssh-keygen -l -f "$key" 2>/dev/null) || continue
            local bits type
            bits=$(echo "$key_info" | awk '{print $1}')
            type=$(echo "$key_info" | grep -oP '\((\w+)\)' | tr -d '()')

            if [[ "$type" == "DSA" ]]; then
                fail "CRITICAL" "$user: DSA key ($key) — deprecated and weak"
            elif [[ "$type" == "RSA" && "$bits" -lt 2048 ]]; then
                fail "HIGH" "$user: RSA-$bits ($key) — too short"
            elif [[ "$type" == "RSA" && "$bits" -lt 4096 ]]; then
                warn "MEDIUM" "$user: RSA-$bits ($key) — consider 4096"
            else
                pass "$user: $type-$bits ($key)"
            fi

            # Check passphrase (encrypted key has Proc-Type/DEK-Info or modern marker)
            if grep -q "ENCRYPTED" "$key" 2>/dev/null; then
                pass "$user: Key is passphrase-protected"
            else
                warn "MEDIUM" "$user: Key has no passphrase"
            fi
        done

        # Check authorized_keys
        local auth_keys="$home_dir/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local ak_count
            ak_count=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$auth_keys" 2>/dev/null) || ak_count=0
            local ak_perms
            ak_perms=$(stat -c '%a' "$auth_keys" 2>/dev/null) || ak_perms="???"
            if [[ "$ak_perms" != "600" && "$ak_perms" != "644" && "$ak_perms" != "400" ]]; then
                fail "HIGH" "$user: authorized_keys perms $ak_perms (should be 600/644)"
            fi
            echo -e "    📋 $user: $ak_count authorized keys"

            # Check for command restrictions
            local unrestricted
            unrestricted=$(grep -c '^ssh-\|^ecdsa-\|^sk-' "$auth_keys" 2>/dev/null) || unrestricted=0
            local restricted
            restricted=$(grep -c '^command=' "$auth_keys" 2>/dev/null) || restricted=0
            if [[ "$unrestricted" -gt 0 && "$restricted" -eq 0 ]]; then
                warn "LOW" "$user: No command restrictions on authorized keys"
            fi
        fi
    done

    if [[ $key_count -eq 0 ]]; then
        echo "    (no SSH keys found)"
    fi
}

audit_known_hosts() {
    echo -e "\n  🌐 Known Hosts Audit"
    echo    "  ─────────────────────────────────────"

    for home_dir in /home/* /root; do
        local kh="$home_dir/.ssh/known_hosts"
        [[ -f "$kh" ]] || continue
        local user
        user=$(basename "$home_dir")
        local count
        count=$(wc -l < "$kh" 2>/dev/null) || count=0

        # Check if hashed
        if grep -q '^|1|' "$kh" 2>/dev/null; then
            pass "$user: known_hosts is hashed ($count entries)"
        else
            local unhashed
            unhashed=$(grep -cv '^|1|' "$kh" 2>/dev/null) || unhashed=0
            if [[ $unhashed -gt 0 ]]; then
                warn "LOW" "$user: $unhashed unhashed entries in known_hosts (run ssh-keygen -H)"
            fi
        fi
    done
}

cmd_scan() {
    echo -e "\n👁️  SPECTER — SSH Security Audit"
    echo    "═══════════════════════════════════════"

    audit_sshd_config
    audit_ssh_keys
    audit_known_hosts

    echo -e "\n  ─────────────────────────────────────"
    if [[ $ISSUES -gt 0 ]]; then
        echo -e "  ${RED}👁️  $ISSUES issues, $WARNINGS warnings${NC}"
    elif [[ $WARNINGS -gt 0 ]]; then
        echo -e "  ${YEL}👁️  0 issues, $WARNINGS warnings${NC}"
    else
        echo -e "  ${GRN}✅ SSH config looks solid${NC}"
    fi
    echo
}

print_help() {
    cat << EOF

👁️  nullsec-specter v$VERSION — SSH Config & Key Auditor (Bash)
   Part of the nullsec freakshow suite.

Usage:
  specter scan       Full SSH security audit
  specter --help     This help

Checks:
  • sshd_config (root login, password auth, port, protocol, X11, etc.)
  • SSH key types & strengths (DSA, RSA bits, ED25519)
  • Key file permissions
  • Passphrase protection
  • authorized_keys permissions & restrictions
  • known_hosts hashing

EOF
}

case "${1:-}" in
    scan)       cmd_scan ;;
    --help|-h)  print_help ;;
    *)          print_help ;;
esac
