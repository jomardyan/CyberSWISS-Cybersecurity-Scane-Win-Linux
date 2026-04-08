#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PIP_BIN="${PIP_BIN:-}"
INSTALL_OPTIONAL=false
SKIP_PYTHON=false
ASSUME_YES=false

usage() {
    cat <<'EOF'
CyberSWISS Linux Runtime Bootstrap

Usage:
  ./setup/install_runtime_linux.sh [--optional] [--skip-python] [--yes]

Options:
  --optional     Install broader optional tooling such as nikto, kubectl, helm, terraform, gvm/openvas.
  --skip-python  Skip "pip install -r requirements.txt".
  --yes          Non-interactive install where supported by the package manager.
  -h, --help     Show this help.
EOF
}

log() {
    printf '[*] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        warn "Run this script as root or via sudo."
        exit 1
    fi
}

detect_pkg_mgr() {
    for mgr in apt-get dnf yum zypper pacman; do
        if command -v "${mgr}" >/dev/null 2>&1; then
            printf '%s\n' "${mgr}"
            return 0
        fi
    done
    return 1
}

run_pkg_install() {
    local pkg_mgr="$1"
    shift
    local -a packages=("$@")
    local -a existing=()
    local pkg

    for pkg in "${packages[@]}"; do
        [[ -n "${pkg}" ]] || continue
        existing+=("${pkg}")
    done

    if [[ "${#existing[@]}" -eq 0 ]]; then
        return 0
    fi

    case "${pkg_mgr}" in
        apt-get)
            apt-get update
            if [[ "${ASSUME_YES}" == true ]]; then
                apt-get install -y "${existing[@]}"
            else
                apt-get install "${existing[@]}"
            fi
            ;;
        dnf)
            if [[ "${ASSUME_YES}" == true ]]; then
                dnf install -y "${existing[@]}"
            else
                dnf install "${existing[@]}"
            fi
            ;;
        yum)
            if [[ "${ASSUME_YES}" == true ]]; then
                yum install -y "${existing[@]}"
            else
                yum install "${existing[@]}"
            fi
            ;;
        zypper)
            if [[ "${ASSUME_YES}" == true ]]; then
                zypper --non-interactive install "${existing[@]}"
            else
                zypper install "${existing[@]}"
            fi
            ;;
        pacman)
            pacman -Sy --needed $([[ "${ASSUME_YES}" == true ]] && printf -- '--noconfirm ') "${existing[@]}"
            ;;
        *)
            warn "Unsupported package manager: ${pkg_mgr}"
            return 1
            ;;
    esac
}

install_python_requirements() {
    if [[ "${SKIP_PYTHON}" == true ]]; then
        log "Skipping Python dependency installation."
        return 0
    fi

    if [[ -z "${PIP_BIN}" ]]; then
        if command -v pip3 >/dev/null 2>&1; then
            PIP_BIN="pip3"
        elif command -v pip >/dev/null 2>&1; then
            PIP_BIN="pip"
        else
            PIP_BIN="${PYTHON_BIN} -m pip"
        fi
    fi

    log "Installing Python dependencies from requirements.txt"
    if [[ "${PIP_BIN}" == *" "* ]]; then
        ${PIP_BIN} install -r "${ROOT_DIR}/requirements.txt"
    else
        "${PIP_BIN}" install -r "${ROOT_DIR}/requirements.txt"
    fi
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --optional) INSTALL_OPTIONAL=true ;;
            --skip-python) SKIP_PYTHON=true ;;
            --yes) ASSUME_YES=true ;;
            -h|--help) usage; exit 0 ;;
            *) warn "Unknown argument: $1"; usage; exit 1 ;;
        esac
        shift
    done

    need_root

    local pkg_mgr
    pkg_mgr="$(detect_pkg_mgr)" || {
        warn "No supported package manager found. Supported: apt-get, dnf, yum, zypper, pacman."
        exit 1
    }

    log "Detected package manager: ${pkg_mgr}"

    local -a base_packages=()
    local -a optional_packages=()

    case "${pkg_mgr}" in
        apt-get)
            base_packages=(
                python3 python3-pip python3-tk bash curl openssl iproute2 iptables nftables sudo
                nmap auditd rsyslog logrotate ufw firewalld cryptsetup mokutil clamav aide
                mysql-client postgresql-client redis-tools docker.io ansible
            )
            optional_packages=(nikto terraform kubectl helm)
            ;;
        dnf)
            base_packages=(
                python3 python3-pip bash curl openssl iproute iptables nftables sudo
                nmap audit rsyslog logrotate firewalld cryptsetup mokutil clamav aide
                mysql postgresql redis docker ansible
            )
            optional_packages=(nikto terraform kubernetes-client helm)
            ;;
        yum)
            base_packages=(
                python3 python3-pip bash curl openssl iproute iptables nftables sudo
                nmap audit rsyslog logrotate firewalld cryptsetup mokutil clamav aide
                mysql postgresql redis docker ansible
            )
            optional_packages=(nikto terraform kubernetes-client helm)
            ;;
        zypper)
            base_packages=(
                python3 python3-pip python3-tk bash curl openssl iproute2 iptables-nft nftables sudo
                nmap audit rsyslog logrotate firewalld cryptsetup mokutil clamav aide
                mariadb-client postgresql redis docker ansible
            )
            optional_packages=(nikto terraform kubernetes-client helm)
            ;;
        pacman)
            base_packages=(
                python python-pip tk bash curl openssl iproute2 iptables nftables sudo
                nmap audit rsyslog logrotate ufw firewalld cryptsetup mokutil clamav aide
                mariadb-clients postgresql redis docker ansible
            )
            optional_packages=(nikto terraform kubectl helm)
            ;;
    esac

    log "Installing base runtime packages"
    run_pkg_install "${pkg_mgr}" "${base_packages[@]}"

    if [[ "${INSTALL_OPTIONAL}" == true ]]; then
        log "Installing optional runtime packages where available"
        if ! run_pkg_install "${pkg_mgr}" "${optional_packages[@]}"; then
            warn "Some optional packages may require extra repositories or manual installation."
        fi
    else
        warn "Skipping optional packages. Re-run with --optional for extra tooling like nikto/terraform/kubectl/helm."
    fi

    install_python_requirements

    cat <<'EOF'

Bootstrap complete.

Manual follow-up may still be needed for:
  - OpenVAS / GVM
  - Nessus
  - Some vendor-specific repos for terraform, helm, kubectl, nikto
  - Service-specific targets such as Docker, Kubernetes, MySQL, PostgreSQL, Redis, IIS, AD

See docs/RUNTIME_REQUIREMENTS.md for details.
EOF
}

main "$@"
