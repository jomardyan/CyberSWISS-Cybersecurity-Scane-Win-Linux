#!/usr/bin/env bash
# =============================================================================
# L29 – Local Privilege Escalation Posture (Linux)
# =============================================================================
# ID       : L29
# Category : Privilege Escalation
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (root recommended for full coverage)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L29_privesc_posture.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L29"
SCRIPT_NAME="Local Privilege Escalation Posture"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true  ;;
        -h|--help) echo "Usage: sudo $0 [--json] [--fix]"; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

add_finding() {
    local id="$1" name="$2" sev="$3" status="$4" detail="$5" remediation="$6"
    local entry
    entry=$(printf '{"id":"%s","name":"%s","severity":"%s","status":"%s","detail":"%s","remediation":"%s","timestamp":"%s"}' \
        "$id" "$name" "$sev" "$status" "$(echo "$detail" | sed 's/"/\\"/g')" "$(echo "$remediation" | sed 's/"/\\"/g')" "$TIMESTAMP")
    if [[ "$FINDINGS" == '[]' ]]; then FINDINGS="[$entry]"; else FINDINGS="${FINDINGS%]},${entry}]"; fi
    if [[ "$JSON_MODE" == false ]]; then
        case "$status" in
            PASS) colour='\033[0;32m' ;; WARN) colour='\033[0;33m' ;; FAIL) colour='\033[0;31m' ;; *) colour='\033[0;36m' ;;
        esac
        printf "${colour}[%s] [%s] %s: %s\033[0m\n" "$status" "$sev" "$id" "$name"
        [[ -n "$detail" ]]      && printf "       Detail : %s\n" "$detail"
        [[ "$status" != "PASS" && -n "$remediation" ]] && printf "\033[0;36m       Remedy : %s\033[0m\n" "$remediation"
    fi
}

# ── C1: Dangerous NOPASSWD sudo entries ──────────────────────────────────────
if [[ -r /etc/sudoers ]]; then
    nopasswd=$(grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' || true)
    if [[ -n "$nopasswd" ]]; then
        count=$(echo "$nopasswd" | wc -l)
        add_finding "${SCRIPT_ID}-C1" "NOPASSWD sudo Entries" "Critical" "FAIL" \
            "${count} NOPASSWD sudoers line(s): $(echo "$nopasswd" | head -3 | tr '\n' ' | ')" \
            "Remove NOPASSWD from /etc/sudoers: visudo. Each user should authenticate before gaining root."
    else
        add_finding "${SCRIPT_ID}-C1" "NOPASSWD sudo Entries" "Critical" "PASS" \
            "No NOPASSWD entries found in sudoers" ""
    fi
else
    add_finding "${SCRIPT_ID}-C1" "NOPASSWD sudo Entries" "Critical" "WARN" \
        "Cannot read /etc/sudoers – run as root for full coverage" \
        "Run this script with sudo for complete sudoers inspection."
fi

# ── C2: Writable directories in root's PATH ──────────────────────────────────
root_path=$(su -s /bin/sh root -c 'echo $PATH' 2>/dev/null || echo "$PATH")
writable_path_dirs=()
IFS=: read -ra path_dirs <<< "$root_path"
for d in "${path_dirs[@]}"; do
    [[ -z "$d" || "$d" == "." ]] && writable_path_dirs+=("$d (dot/empty in PATH)") && continue
    if [[ -d "$d" && -w "$d" ]]; then
        writable_path_dirs+=("$d")
    fi
done

if [[ "${#writable_path_dirs[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Writable Dirs in root PATH" "Critical" "FAIL" \
        "Writable PATH dirs: ${writable_path_dirs[*]}" \
        "Remove world-writable or user-writable directories from root's PATH to prevent PATH hijacking."
else
    add_finding "${SCRIPT_ID}-C2" "Writable Dirs in root PATH" "Critical" "PASS" \
        "No writable directories found in root's PATH" ""
fi

# ── C3: World-writable systemd unit files ────────────────────────────────────
ww_units=$(find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -o -name '*.timer' 2>/dev/null \
    | xargs -I{} sh -c 'test -w "{}" && echo "{}"' 2>/dev/null | head -10 || true)
if [[ -n "$ww_units" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Writable systemd Unit Files" "Critical" "FAIL" \
        "World-writable unit files: $(echo "$ww_units" | tr '\n' ' | ')" \
        "Fix permissions: chmod o-w <unit_file>. A writable service file allows full root code execution."
else
    add_finding "${SCRIPT_ID}-C3" "Writable systemd Unit Files" "Critical" "PASS" \
        "No world-writable systemd unit files found" ""
fi

# ── C4: Polkit misconfiguration ──────────────────────────────────────────────
polkit_ver=""
if command -v pkaction &>/dev/null; then
    polkit_ver=$(pkaction --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
fi

# CVE-2021-4034 (pkexec) – affects polkit < 0.121
if [[ -n "$polkit_ver" ]]; then
    major="${polkit_ver%%.*}"
    minor="${polkit_ver##*.}"
    if (( major == 0 && minor < 121 )); then
        add_finding "${SCRIPT_ID}-C4" "Polkit pkexec Vulnerability (CVE-2021-4034)" "Critical" "FAIL" \
            "polkit version ${polkit_ver} is vulnerable to CVE-2021-4034 (PwnKit – local root privesc)" \
            "Update polkit: apt-get install --only-upgrade policykit-1 OR dnf update polkit"
    else
        add_finding "${SCRIPT_ID}-C4" "Polkit Version" "High" "PASS" \
            "polkit ${polkit_ver} installed – not vulnerable to CVE-2021-4034" ""
    fi
else
    add_finding "${SCRIPT_ID}-C4" "Polkit Version" "Info" "INFO" \
        "polkit not found or version not determinable" ""
fi

# ── C5: SUID abuse candidates (known exploitation paths) ─────────────────────
DANGEROUS_SUID=(
    "/usr/bin/python" "/usr/bin/python2" "/usr/bin/python3"
    "/usr/bin/perl" "/usr/bin/ruby" "/usr/bin/lua" "/usr/bin/awk"
    "/usr/bin/find" "/usr/bin/vim" "/usr/bin/nano" "/usr/bin/less" "/usr/bin/more"
    "/usr/bin/tee" "/usr/bin/cp" "/usr/bin/mv" "/usr/bin/bash" "/bin/bash"
    "/usr/bin/sh" "/bin/sh" "/usr/bin/nc" "/usr/bin/ncat" "/usr/bin/nmap"
    "/usr/bin/curl" "/usr/bin/wget" "/usr/bin/git" "/usr/bin/zip" "/usr/bin/unzip"
    "/bin/tar" "/usr/bin/tar" "/usr/bin/rsync" "/usr/bin/env"
)

dangerous_found=()
for bin in "${DANGEROUS_SUID[@]}"; do
    if [[ -f "$bin" ]] && [[ -u "$bin" ]]; then
        dangerous_found+=("$bin")
    fi
done

if [[ "${#dangerous_found[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "SUID on Dangerous Binaries" "Critical" "FAIL" \
        "SUID set on exploitation-capable binaries: ${dangerous_found[*]}" \
        "Remove SUID: chmod u-s <binary>. These binaries allow trivial root shell via GTFOBins."
else
    add_finding "${SCRIPT_ID}-C5" "SUID on Dangerous Binaries" "Critical" "PASS" \
        "No SUID bits found on known GTFOBins-style abuse binaries" ""
fi

# ── C6: Kernel exploit exposure (kernel version checks) ──────────────────────
kernel_ver=$(uname -r)
kernel_base=$(echo "$kernel_ver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")
k_major=$(echo "$kernel_base" | cut -d. -f1)
k_minor=$(echo "$kernel_base" | cut -d. -f2)
k_patch=$(echo "$kernel_base" | cut -d. -f3)

add_finding "${SCRIPT_ID}-C6" "Kernel Version" "Info" "INFO" \
    "Running kernel: ${kernel_ver}" \
    ""

# Check for very old kernels (< 5.4 is end-of-support on most mainstream distros)
if (( k_major < 5 )) || (( k_major == 5 && k_minor < 4 )); then
    add_finding "${SCRIPT_ID}-C6b" "Outdated Kernel (PrivEsc Risk)" "Critical" "FAIL" \
        "Kernel ${kernel_ver} is below 5.4 – multiple known local privesc CVEs apply (Dirty COW, OverlayFS, Netfilter)" \
        "Update kernel: apt-get install --install-recommends linux-generic OR dnf update kernel"
fi

# ── C7: Capabilities on binaries ─────────────────────────────────────────────
if command -v getcap &>/dev/null; then
    caps=$(getcap -r / 2>/dev/null | grep -v 'cap_net_admin\|cap_net_raw\|cap_net_bind_service\|cap_chown\|cap_dac_override\|cap_sys_chroot' | head -20 || true)
    # Flag escalating capabilities
    dangerous_caps=$(echo "$caps" | grep -E 'cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_sys_rawio|cap_mknod|=ep' || true)
    if [[ -n "$dangerous_caps" ]]; then
        add_finding "${SCRIPT_ID}-C7" "Dangerous Capabilities on Binaries" "Critical" "FAIL" \
            "Binaries with privesc-capable capabilities: $(echo "$dangerous_caps" | head -5 | tr '\n' ' | ')" \
            "Remove capability: setcap -r <binary>. cap_setuid/cap_sys_admin can yield root shell."
    else
        cap_count=$(getcap -r / 2>/dev/null | wc -l || echo 0)
        add_finding "${SCRIPT_ID}-C7" "Binary Capabilities" "High" "PASS" \
            "${cap_count} capabilities found – no dangerous escalation capabilities detected" ""
    fi
else
    add_finding "${SCRIPT_ID}-C7" "Binary Capabilities" "High" "INFO" \
        "getcap not available – install libcap2-bin for capability auditing" ""
fi

# ── C8: Writable /etc/passwd or /etc/shadow ──────────────────────────────────
for f in /etc/passwd /etc/shadow /etc/sudoers; do
    if [[ -w "$f" ]] && [[ "$(stat -c '%a' "$f")" != "640" || $(id -u) -ne 0 ]]; then
        add_finding "${SCRIPT_ID}-C8-$(basename $f)" "Writable $f" "Critical" "FAIL" \
            "$f is writable by the current process – direct privilege escalation path" \
            "Fix: chmod 644 /etc/passwd; chmod 640 /etc/shadow; chmod 440 /etc/sudoers"
    fi
done
# Check normal permissions
passwd_perm=$(stat -c '%a' /etc/passwd 2>/dev/null || echo "?")
shadow_perm=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "?")
if [[ "$passwd_perm" == "644" || "$passwd_perm" == "644" ]]; then
    add_finding "${SCRIPT_ID}-C8" "Critical File Permissions" "High" "PASS" \
        "/etc/passwd:${passwd_perm}  /etc/shadow:${shadow_perm}" ""
fi

# ── C9: Docker group membership (root-equivalent) ───────────────────────────
if getent group docker &>/dev/null; then
    docker_members=$(getent group docker | cut -d: -f4)
    if [[ -n "$docker_members" ]]; then
        add_finding "${SCRIPT_ID}-C9" "Docker Group Members (Root-Equivalent)" "Critical" "FAIL" \
            "Users in docker group (bypasses all access controls): ${docker_members}" \
            "Remove non-admin users from docker group: gpasswd -d <user> docker. Use rootless Docker instead."
    else
        add_finding "${SCRIPT_ID}-C9" "Docker Group Members" "High" "PASS" \
            "No non-system users in docker group" ""
    fi
fi

# ── C10: NFS mounts with no_root_squash ──────────────────────────────────────
if [[ -f /etc/exports ]]; then
    nrs=$(grep -v '^\s*#' /etc/exports 2>/dev/null | grep 'no_root_squash' || true)
    if [[ -n "$nrs" ]]; then
        add_finding "${SCRIPT_ID}-C10" "NFS no_root_squash Export" "Critical" "FAIL" \
            "NFS exports with no_root_squash: $(echo "$nrs" | head -3 | tr '\n' ' | ')" \
            "Replace no_root_squash with root_squash in /etc/exports; then: exportfs -ra"
    else
        add_finding "${SCRIPT_ID}-C10" "NFS no_root_squash Export" "High" "PASS" \
            "No no_root_squash NFS exports found" ""
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix mode: applying safe automated remediations..." >&2
    # Fix world-writable systemd units
    if [[ -n "${ww_units:-}" ]]; then
        echo "$ww_units" | while IFS= read -r unit; do
            [[ -n "$unit" ]] && chmod o-w "$unit" && echo "Fixed: removed other-write from $unit" >&2
        done
    fi
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_privesc_posture" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} – ${HOSTNAME_VAL} ==="
    FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
    WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
    TOTAL=$(printf '%s\n' "$FINDINGS" | grep -c '"id":' || true)
    echo "Summary: ${TOTAL} finding(s), ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"
fi

FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
if [[ "$FAIL_COUNT" -gt 0 ]]; then exit 2; fi
if [[ "$WARN_COUNT" -gt 0 ]]; then exit 1; fi
exit 0
