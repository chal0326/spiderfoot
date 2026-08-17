#!/usr/bin/env bash
#
# Install the external binaries used by SpiderFoot's bundled "Tool - " modules,
# then record their locations in the SpiderFoot configuration.
#
# These tools need no API key; they only need to be present on the system and
# pointed at. By default only the tools which act on IP addresses and hosts are
# installed. Use --all for the full set, which adds the web, domain and source
# repository tools.
#
# Usage:
#   ./sfinstall-tools.sh              # IP/host tools (nmap, nbtscan, ...)
#   ./sfinstall-tools.sh --all        # every bundled tool
#   ./sfinstall-tools.sh --dry-run    # print what would be installed
#
# Licence: MIT

set -o pipefail

INSTALL_ALL=0
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --all) INSTALL_ALL=1 ;;
        --dry-run|-n) DRY_RUN=1 ;;
        -h|--help) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# --- platform detection -----------------------------------------------------

PKG=""
SUDO=""

if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

if command -v apt-get >/dev/null 2>&1; then
    PKG="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
elif command -v brew >/dev/null 2>&1; then
    PKG="brew"
    SUDO=""
elif command -v pacman >/dev/null 2>&1; then
    PKG="pacman"
else
    echo "No supported package manager found (apt, dnf, brew, pacman)." >&2
    echo "Install the tools manually, then run: ./sfapikeys.py tools --apply" >&2
    exit 1
fi

echo "Package manager: $PKG"
[ "$DRY_RUN" -eq 1 ] && echo "(dry run - nothing will be installed)"
echo

run() {
    echo "  \$ $*"
    if [ "$DRY_RUN" -eq 0 ]; then
        "$@" || return 1
    fi
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

FAILED=""

# --- system packages --------------------------------------------------------

pkg_install() {
    # $1 = friendly name, $2 = binary to test for, rest = package name per PKG
    local name="$1" bin="$2" apt_p="$3" dnf_p="$4" brew_p="$5" pac_p="$6"
    local pkg=""

    if have "$bin"; then
        echo "[ok]      $name already installed ($(command -v "$bin"))"
        return 0
    fi

    case "$PKG" in
        apt) pkg="$apt_p" ;;
        dnf) pkg="$dnf_p" ;;
        brew) pkg="$brew_p" ;;
        pacman) pkg="$pac_p" ;;
    esac

    if [ -z "$pkg" ] || [ "$pkg" = "-" ]; then
        echo "[skip]    $name has no $PKG package; install manually"
        return 0
    fi

    echo "[install] $name"
    case "$PKG" in
        apt) run $SUDO apt-get install -y "$pkg" ;;
        dnf) run $SUDO dnf install -y "$pkg" ;;
        brew) run brew install "$pkg" ;;
        pacman) run $SUDO pacman -S --noconfirm "$pkg" ;;
    esac || FAILED="$FAILED $name"
}

if [ "$PKG" = "apt" ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "Refreshing package lists..."
    run $SUDO apt-get update -qq
    echo
fi

echo "=== IP / host tools ==="
#          name          binary        apt            dnf            brew           pacman
pkg_install "Nmap"        nmap          nmap           nmap           nmap           nmap
pkg_install "nbtscan"     nbtscan       nbtscan        nbtscan        -              -
pkg_install "onesixtyone" onesixtyone   onesixtyone    onesixtyone    onesixtyone    -
pkg_install "testssl.sh"  testssl.sh    testssl.sh     testssl        testssl        testssl.sh

# Nuclei ships as a Go binary rather than a distro package on most systems.
if have nuclei; then
    echo "[ok]      Nuclei already installed ($(command -v nuclei))"
elif [ "$PKG" = "brew" ]; then
    echo "[install] Nuclei"
    run brew install nuclei || FAILED="$FAILED Nuclei"
elif have go; then
    echo "[install] Nuclei (via go install)"
    run go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
        || FAILED="$FAILED Nuclei"
    echo "          ensure \$(go env GOPATH)/bin is on your PATH"
else
    echo "[skip]    Nuclei needs Go, or a release binary from"
    echo "          https://github.com/projectdiscovery/nuclei/releases"
fi

# --- optional wider set -----------------------------------------------------

if [ "$INSTALL_ALL" -eq 1 ]; then
    echo
    echo "=== Web / domain / repository tools ==="
    pkg_install "WhatWeb"   whatweb   whatweb   whatweb   whatweb   -
    pkg_install "Wapiti"    wapiti    wapiti    -         -         -

    for spec in "dnstwist:dnstwist" "wafw00f:wafw00f" "snallygaster:snallygaster"; do
        bin="${spec%%:*}"; pip_pkg="${spec##*:}"
        if have "$bin"; then
            echo "[ok]      $bin already installed ($(command -v "$bin"))"
        elif have pip3; then
            echo "[install] $bin (pip)"
            run pip3 install --user "$pip_pkg" || FAILED="$FAILED $bin"
        else
            echo "[skip]    $bin needs pip3"
        fi
    done

    if have retire; then
        echo "[ok]      retire.js already installed ($(command -v retire))"
    elif have npm; then
        echo "[install] retire.js (npm)"
        run npm install -g retire || FAILED="$FAILED retire.js"
    else
        echo "[skip]    retire.js needs npm"
    fi

    if have trufflehog; then
        echo "[ok]      TruffleHog already installed ($(command -v trufflehog))"
    elif [ "$PKG" = "brew" ]; then
        run brew install trufflehog || FAILED="$FAILED TruffleHog"
    else
        echo "[skip]    TruffleHog: see https://github.com/trufflesecurity/trufflehog"
    fi
fi

# --- record the paths in SpiderFoot -----------------------------------------

echo
if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run complete. Re-run without --dry-run to install."
    exit 0
fi

SF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -x "$SF_DIR/sfapikeys.py" ]; then
    echo "Recording tool paths in the SpiderFoot configuration..."
    if [ "$INSTALL_ALL" -eq 1 ]; then
        "$SF_DIR/sfapikeys.py" tools --apply
    else
        "$SF_DIR/sfapikeys.py" tools --ip-only --apply
    fi
else
    echo "Run './sfapikeys.py tools --apply' to record the tool paths."
fi

if [ -n "$FAILED" ]; then
    echo
    echo "Some tools did not install:$FAILED"
    echo "Install them manually, then re-run: ./sfapikeys.py tools --apply"
    exit 1
fi
