#!/usr/bin/env bash
# -------------------------------------------------------------------------
# Script Name:    linux-zabbix-install.sh
# Description:    Multi-distro installer for Zabbix Agent (v1 and v2).
#                 Supports Debian/Ubuntu and RHEL-like systems (including
#                 legacy RHEL5) with automatic repository management.
#
#                 - Detects OS and version (even without /etc/os-release).
#                 - Removes old repo definitions when necessário.
#                 - Instala o zabbix-release correto (5.0, 6.x, 7.x).
#                 - Instala Zabbix Agent 2 quando disponível, ou cai
#                   para o agente clássico (v1) quando necessário.
#                 - Configura o agente e gerencia o serviço.
#
#                 - Comportamento padrão agora:
#                   * Se já existir Zabbix Agent instalado e você NÃO
#                     passar --repo nem --force:
#                       - Mantém o mesmo branch (ex.: 5.0, 6.0, 7.0).
#                       - NÃO atualiza o pacote do agente; apenas
#                         ajusta configuração e serviço.
#
# Author:         Lucas Bonfim de Oliveira Lima
# LinkedIn:       https://linkedin.com/in/soulucasbonfim
# Creation Date:  2025-08-28
#
# Usage:
#   sudo ./linux-zabbix-install.sh \
#     --server <IP1,IP2> \
#     [--active <IP>] \
#     [--repo <X.Y>] \
#     [--agent-flavor <1|2|auto>] \
#     [--force] [--verbose] [--dry-run] \
#     [--cleanup-v1-agent] [--with-tools] \
#     [--insecure]
#
# Options:
#   --server            Address/FQDN of the Zabbix Proxy/Server for passive checks (Server=).
#   --active            Address/FQDN of the Zabbix Server/Proxy for active checks (ServerActive=).
#   --repo              Force repo branch (e.g., 5.0, 6.0, 6.4, 7.0, 7.4).
#   --agent-flavor      Which agent to install:
#                         2    = force zabbix-agent2 only (error if unavailable)
#                         1    = force classic zabbix-agent (v1)
#                         auto = prefer agent2, fallback to agent (default)
#   --force             Force reinstall/downgrade of the agent package even if one is already installed.
#   --verbose           Display full command output instead of suppressing it.
#   --dry-run           Show what commands would be run without actually executing them.
#   --cleanup-v1-agent  Stop, disable, and remove the classic zabbix-agent (v1) before install.
#   --with-tools        Also install zabbix-get and zabbix-sender when available.
#   --insecure          Ignore SSL certificate errors (curl -k).
#   --no-gpg-check      Disable RPM/DNF/YUM package signature verification (also implied by --insecure unless overridden).
#   --gpg-check         Enforce signature verification even if --insecure is used.
#
# Notes:
#   - Script must be executed as root.
#   - On Ubuntu 24.04 and Debian 13, repo fallback is applied automatically.
#   - For legacy RHEL5, HTTPS is not used; HTTP repo and Agent 1 (5.0.x) are used.
#   - By default, if an agent package is already installed and --force is NOT
#     provided, the script will NOT change the agent package version; it will
#     only (re)configure and manage the service.
# -------------------------------------------------------------------------

set -euo pipefail

# -------------------------------------------------------------------------
# Locale Standardization
# -------------------------------------------------------------------------
if [[ "${LC_ALL:-}" != "C" || "${LANG:-}" != "C" || "${LANGUAGE:-}" != "C" ]]; then
    export LC_ALL=C
    export LANG=C
    export LANGUAGE=C
fi

# -------------------------------------------------------------------------
# Root check
# -------------------------------------------------------------------------
if (( EUID != 0 )); then
    echo "[$(date '+%F %T')] ❌ [ERROR] Must run as root" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# -------------------------------------------------------------------------
# Global Variables
# -------------------------------------------------------------------------
SERVER=""
ACTIVE=""
REPO_OVERRIDE=""
AGENT_FLAVOR="auto"    # 1 | 2 | auto
FORCE=0
REPO_BRANCH=""
REPO_FALLBACK=""
DRY_RUN=0
VERBOSE=0
CLEANUP_V1=0
INSTALL_TOOLS=0
CURL_OPTS=()
INSECURE=0

NO_GPGCHECK=0
NO_GPGCHECK_SET=0
PKG_NOGPGCHECK_ARGS=()
RPM_NOGPG_ARGS=()
LAST_MAY_FAIL_RC=0

RPM_OSDIR=""
RPM_MAJOR=""

DISTRO_ID=""
DISTRO_VER=""
DISTRO_LIKE=""   # from /etc/os-release ID_LIKE (can be empty)
ARCH=""
ZBX_BASE_URL_RPM="https://repo.zabbix.com/zabbix"

# -------------------------------------------------------------------------
# Argument Parsing
# -------------------------------------------------------------------------
print_usage() {
    cat <<EOF
Usage:
  $0 --server <IP1,IP2> [options]

Mandatory:
  --server <value>          Zabbix Proxy/Server for passive checks (Server=).

Optional:
  --active <value>          Zabbix Server/Proxy for active checks (ServerActive=).
  --repo <X.Y>              Force repo branch (5.0, 6.0, 6.4, 7.0, 7.4).
  --agent-flavor <1|2|auto> Which agent to install (default: auto).
  --force                   Force reinstall/downgrade of agent package.
  --verbose                 Show full command output.
  --dry-run                 Show commands, do not execute.
  --cleanup-v1-agent        Remove classic zabbix-agent (v1) before install.
  --with-tools              Also install zabbix-get and zabbix-sender.
  --insecure                Ignore SSL certificate errors (curl -k).
  --no-gpg-check            Disable RPM/DNF/YUM package signature verification (also implied by --insecure unless overridden).
  --gpg-check               Enforce signature verification even if --insecure is used.
  -h, --help                Show this help.

Default behaviour:
  - If a Zabbix agent package is already installed and you do NOT specify
    --force, the script will reuse the existing agent package/version and
    only (re)configure it.

Examples:
  $0 --server zbx-proxies.ACME.NET
  $0 --server zbx-proxies.ACME.NET --active zbx-server.ACME.NET --repo 6.4
  $0 --server zbx-proxies.ACME.NET --agent-flavor 1 --with-tools
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            SERVER="${2:-}"; shift 2 ;;
        --active)
            ACTIVE="${2:-}"; shift 2 ;;
        --repo)
            REPO_OVERRIDE="${2:-}"; shift 2 ;;
        --agent-flavor)
            AGENT_FLAVOR="${2:-auto}"
            case "$AGENT_FLAVOR" in
                1|2|auto) ;;
                *)
                    echo "[!] Invalid value for --agent-flavor: '$AGENT_FLAVOR' (use 1, 2, or auto)" >&2
                    exit 1 ;;
            esac
            shift 2 ;;
        --force)
            FORCE=1; shift ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        --verbose)
            VERBOSE=1; shift ;;
        --cleanup-v1-agent)
            CLEANUP_V1=1; shift ;;
        --with-tools)
            INSTALL_TOOLS=1; shift ;;
		--insecure)
            INSECURE=1
            CURL_OPTS+=(-k)
            shift ;;
        --no-gpg-check)
            NO_GPGCHECK=1
            NO_GPGCHECK_SET=1
            shift ;;
        --gpg-check)
            NO_GPGCHECK=0
            NO_GPGCHECK_SET=1
            shift ;;
        -h|--help)
            print_usage
            exit 0 ;;
        *)
            echo "[!] Unknown parameter: $1" >&2
            print_usage
            exit 1 ;;
    esac
done

[[ -n "$SERVER" ]] || { echo "[!] Missing required parameter: --server" >&2; print_usage; exit 1; }

# If --insecure was used and user did not explicitly choose gpg behavior, default to no-gpg-check
if [[ $INSECURE -eq 1 && $NO_GPGCHECK_SET -eq 0 ]]; then
    NO_GPGCHECK=1
fi

if [[ $NO_GPGCHECK -eq 1 ]]; then
    PKG_NOGPGCHECK_ARGS=(--nogpgcheck)
    RPM_NOGPG_ARGS=(--nosignature --nodigest)
else
    PKG_NOGPGCHECK_ARGS=()
    RPM_NOGPG_ARGS=()
fi

# -------------------------------------------------------------------------
# Keep script open in memory and remove file from disk
# -------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 && -f "$0" && "$0" != /dev/fd/* && "$0" != /proc/self/fd/* ]]; then
    rm -f -- "$0" 2>/dev/null || true
fi

# -------------------------------------------------------------------------
# Logging + Spinner Colors (AUTO, TTY-safe, NO_COLOR aware)
# -------------------------------------------------------------------------
ENABLE_COLORS=0

if [[ "${NO_COLOR:-}" != "1" ]]; then
  if [[ -t 1 && -n "${TERM:-}" && "${TERM:-}" != "dumb" ]]; then
    if command -v tput >/dev/null 2>&1; then
      _tput_colors="$(tput colors 2>/dev/null || echo 0)"
      if [[ "${_tput_colors}" =~ ^[0-9]+$ ]] && (( _tput_colors >= 8 )); then
        ENABLE_COLORS=1
      fi
    else
      ENABLE_COLORS=1
    fi
  fi
fi

if (( ENABLE_COLORS )); then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'

  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

# Simple level tags (colorized when enabled)
TAG_INFO="${C_BLUE}[*]${C_RESET}"
TAG_WARN="${C_YELLOW}[!]${C_RESET}"
TAG_ERR="${C_RED}[✗]${C_RESET}"
TAG_OK="${C_GREEN}[+]${C_RESET}"

# Spinner visuals (dim)
SPIN_DIM="${C_DIM}"
SPIN_RESET="${C_RESET}"

# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log()  { printf "%s[%s]%s %s %s\n" "$C_DIM" "$(get_timestamp)" "$C_RESET" "$TAG_INFO" "$*"; }
warn() { printf "%s[%s]%s %s %s\n" "$C_DIM" "$(get_timestamp)" "$C_RESET" "$TAG_WARN" "$*" >&2; }
die()  { printf "%s[%s]%s %s %s\n" "$C_DIM" "$(get_timestamp)" "$C_RESET" "$TAG_ERR"  "$*" >&2; exit 1; }
ok()  { printf "%s%s%s %s\n" "$C_DIM" "$C_RESET" "$TAG_OK" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Função para comandos rápidos que não devem sujar a tela (ex: sed, echo, rm)
# Só mostra erro se falhar
run_silent() {
    local cmd_str="$*"
	
	if [[ $DRY_RUN -eq 1 ]]; then
        log "[DRY] $cmd_str"
        return 0
	fi
	
    if [[ $VERBOSE -eq 1 ]]; then
        log "Exec: $cmd_str"
        "$@"
        return $?
    fi
    # Executa e silencia stdout/stderr, a menos que falhe
    local out
    out="$("$@" 2>&1)" || { echo "$out" >&2; die "Command failed: $cmd_str"; }
}

tmpfile_create() {
    if have mktemp; then
        mktemp
        return 0
    fi
    # Fallback (best-effort). Ensure file exists.
    local f="/tmp/zbx.$$.$RANDOM.tmp"
    : > "$f" 2>/dev/null || true
    echo "$f"
}

ver_ge_xy() {
    # Compare X.Y numbers only
    local a="$1" b="$2"
    local a1 a2 b1 b2
    IFS=. read -r a1 a2 _ <<<"$a"
    IFS=. read -r b1 b2 _ <<<"$b"
    a1=${a1:-0}; a2=${a2:-0}; b1=${b1:-0}; b2=${b2:-0}
    (( a1 > b1 )) || (( a1 == b1 && a2 >= b2 ))
}

# Função visual para comandos demorados (dnf, apt, curl)
execute() {
  local cmd_str="$*"

  if [[ $DRY_RUN -eq 1 ]]; then
    log "[DRY] $cmd_str"
    return 0
  fi

  if [[ $VERBOSE -eq 1 ]]; then
    log "Exec: $cmd_str"
    if ! "$@"; then die "Command failed: $cmd_str"; fi
    return 0
  fi

  # One-line progress with spinner (TTY only)
  local prefix
  prefix="$(printf "%s[%s]%s %s    Processing:%s " \
    "$C_DIM" "$(get_timestamp)" "$C_RESET" "${C_CYAN}" "$C_RESET")"

  local msg="${cmd_str}"
  # Keep the line short and stable
  if ((${#msg} > 60)); then
    msg="${msg:0:57}..."
  fi

  printf "%s%s" "$prefix" "$msg"

  local temp_out pid delay spinstr exit_code
  temp_out="$(tmpfile_create)"

  "$@" >"$temp_out" 2>&1 &
  pid=$!
  delay=0.1
  spinstr='|/-\'

  # Hide cursor if possible
  tput civis 2>/dev/null || true

  # Spinner only if stdout is a TTY; otherwise it will just run quietly
  if [[ -t 1 ]]; then
    while ps -p "$pid" >/dev/null 2>&1; do
      local ch="${spinstr:0:1}"
      spinstr="${spinstr:1}${ch}"
      printf " %s%s%s" "$SPIN_DIM" "$ch" "$SPIN_RESET"
      sleep "$delay"
      printf "\b\b"
    done
  else
    wait "$pid" || true
  fi

  if wait "$pid"; then
    exit_code=0
  else
    exit_code=$?
  fi

  tput cnorm 2>/dev/null || true

  if [[ $exit_code -eq 0 ]]; then
    printf " %s[OK]%s\n" "$C_GREEN" "$C_RESET"
    rm -f "$temp_out"
  else
    printf " %s[FAIL]%s\n" "$C_RED" "$C_RESET"
    cat "$temp_out" >&2
    rm -f "$temp_out"
    die "Command failed: $cmd_str"
  fi
}

execute_may_fail() {
  local cmd_str="$*"

  if [[ $DRY_RUN -eq 1 ]]; then
    log "[DRY][IGNORE] $cmd_str"
    LAST_MAY_FAIL_RC=0
    return 0
  fi

  local prefix
  prefix="$(printf "%s[%s]%s %s Attempting:%s " \
    "$C_DIM" "$(get_timestamp)" "$C_RESET" "${C_CYAN}" "$C_RESET")"

  local msg="${cmd_str}"
  if ((${#msg} > 60)); then
    msg="${msg:0:57}..."
  fi

  printf "%s%s" "$prefix" "$msg"

  local temp_out pid delay spinstr exit_code
  temp_out="$(tmpfile_create)"

  "$@" >"$temp_out" 2>&1 &
  pid=$!
  delay=0.1
  spinstr='|/-\'

  tput civis 2>/dev/null || true

  if [[ -t 1 ]]; then
    while ps -p "$pid" >/dev/null 2>&1; do
      local ch="${spinstr:0:1}"
      spinstr="${spinstr:1}${ch}"
      printf " %s%s%s" "$SPIN_DIM" "$ch" "$SPIN_RESET"
      sleep "$delay"
      printf "\b\b"
    done
  else
    wait "$pid" || true
  fi

  if wait "$pid"; then
    exit_code=0
  else
    exit_code=$?
  fi

  tput cnorm 2>/dev/null || true

  LAST_MAY_FAIL_RC="$exit_code"

  if [[ $exit_code -eq 0 ]]; then
    printf " %s[OK]%s\n" "$C_GREEN" "$C_RESET"
  else
    printf " %s[SKIP]%s\n" "$C_YELLOW" "$C_RESET"
    tail -n 50 "$temp_out" >&2 || true
  fi

  rm -f "$temp_out"
  return 0
}

# -------------------------------------------------------------------------
# Insecure Mode Helpers
# -------------------------------------------------------------------------
sync_insecure_repo_settings_rpm() {
    # Ensure we never leave sslverify=0 behind when --insecure is NOT used.
    # When --insecure is used, apply sslverify=0 to ALL repo sections in Zabbix repo files only.
    local f
    shopt -s nullglob

    for f in /etc/yum.repos.d/zabbix*.repo; do
        # Remove any previous sslverify directives (from prior runs).
        run_silent sed -i -e '/^[[:space:]]*sslverify[[:space:]]*=/d' "$f"

        if [[ $INSECURE -eq 1 ]]; then
            # Add sslverify=0 right after every repo section header (e.g., [zabbix], [zabbix-non-supported], etc.).
            run_silent sed -i -e '/^\[[^]]*\]$/a sslverify=0' "$f"
        fi
    done

    shopt -u nullglob
}

# -------------------------------------------------------------------------
# OS Detection
# -------------------------------------------------------------------------
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
		DISTRO_ID="$(printf '%s' "${ID:-unknown}" | tr '[:upper:]' '[:lower:]')"
        DISTRO_VER="${VERSION_ID:-}"
        DISTRO_LIKE="$(printf '%s' "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"

    elif [[ -f /etc/redhat-release ]]; then
        DISTRO_ID="rhel"
        DISTRO_VER="$(grep -oE 'release[[:space:]]+[0-9]+\.[0-9]+' /etc/redhat-release | awk '{print $2}')"
        if [[ -z "$DISTRO_VER" ]]; then
            warn "Unable to extract version from /etc/redhat-release"
        fi

    elif have lsb_release; then
        DISTRO_ID="$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]')"
        DISTRO_VER="$(lsb_release -sr 2>/dev/null || true)"

    else
        die "Unable to detect OS: missing /etc/os-release, /etc/redhat-release and lsb_release."
    fi

    ARCH="$(uname -m 2>/dev/null || echo "unknown")"
    log "Detected distribution: ${DISTRO_ID} ${DISTRO_VER:-<unknown>} (${ARCH})"
}

is_deb() {
    [[ "$DISTRO_ID" =~ (debian|ubuntu) ]] || [[ "$DISTRO_LIKE" == *debian* ]] || [[ "$DISTRO_LIKE" == *ubuntu* ]]
}

is_rpm() {
    [[ "$DISTRO_ID" =~ (rhel|centos|rocky|almalinux|ol|fedora|amzn) ]] || [[ "$DISTRO_LIKE" == *rhel* ]] || [[ "$DISTRO_LIKE" == *fedora* ]] || [[ "$DISTRO_LIKE" == *centos* ]]
}

# -------------------------------------------------------------------------
# Repo Tag Mapping
# -------------------------------------------------------------------------
map_repo_tag() {
    local id="$1" ver="$2"
    case "$id" in
        ubuntu)
            case "$ver" in
                24.04|23.10) REPO_FALLBACK="mapped to 22.04"; echo "22.04" ;;
                *) echo "$ver" ;;
            esac
            ;;
        debian)
            case "$ver" in
                13) REPO_FALLBACK="mapped to 12"; echo "12" ;;
                *) echo "$ver" ;;
            esac
            ;;
        rhel|centos|rocky|almalinux|ol)
            local major="${ver%%.*}"
            echo "el${major}"
            ;;
		fedora)
            # Best-effort mapping: Zabbix RPM repos are EL-oriented; map Fedora to nearest EL major.
            local fmaj="${ver%%.*}"
            if [[ "$fmaj" -ge 40 ]]; then
                echo "el9"
            else
                echo "el8"
            fi
            ;;
		amzn)
            # Amazon Linux: VERSION_ID is typically "2" or "2023"
            case "$ver" in
                2|2.*) echo "amzn2" ;;
                2023|2023.*) echo "amzn2023" ;;
                *) die "Unsupported Amazon Linux version: $ver" ;;
            esac
            ;;
        *)
            die "Unsupported distribution: $id $ver"
            ;;
    esac
}

init_rpm_repo_context() {
    # Determine repo "osdir" used by repo.zabbix.com for RPM trees.
    # This does NOT change package suffix (.el9, .amzn2023, etc.), only the directory path.
    RPM_OSDIR="rhel"
    case "$DISTRO_ID" in
        rocky) RPM_OSDIR="rocky" ;;
        almalinux) RPM_OSDIR="alma" ;;
        ol|oraclelinux) RPM_OSDIR="oracle" ;;
        centos) RPM_OSDIR="centos" ;;
        rhel) RPM_OSDIR="rhel" ;;
        amzn) RPM_OSDIR="amazonlinux" ;;
        fedora) RPM_OSDIR="rhel" ;;   # Fedora is mapped to EL in your map_repo_tag()
        *) RPM_OSDIR="rhel" ;;
    esac

    # Determine "major" directory component from REPO_TAG
    case "${REPO_TAG:-}" in
        el*) RPM_MAJOR="${REPO_TAG#el}" ;;
        amzn2) RPM_MAJOR="2" ;;
        amzn2023) RPM_MAJOR="2023" ;;
        *) RPM_MAJOR="" ;;
    esac
}

rpm_repo_root_candidates() {
    # Echo candidate roots (without trailing /arch) in priority order.
    # Format: <base>/<branch>/<prefix>/<osdir>/<major>
    local repo_branch="$1"
    local osdir="${RPM_OSDIR}"
    local maj="${RPM_MAJOR}"

    # Primary then fallbacks (helpful when Zabbix publishes in another osdir)
    local -a osdirs=("$osdir")
    if [[ "$osdir" != "rhel" ]]; then osdirs+=("rhel"); fi
    if [[ "${REPO_TAG}" == el* ]]; then
        osdirs+=("centos" "rocky" "alma" "oracle")
    fi

    local -a prefixes=("release" "stable" "")  # "" => legacy layout
    local p o

    for p in "${prefixes[@]}"; do
        for o in "${osdirs[@]}"; do
            if [[ -n "$p" ]]; then
                printf '%s/%s/%s/%s/%s\n' "$ZBX_BASE_URL_RPM" "$repo_branch" "$p" "$o" "$maj"
            else
                printf '%s/%s/%s/%s\n' "$ZBX_BASE_URL_RPM" "$repo_branch" "$o" "$maj"
            fi
        done
    done
}

# -------------------------------------------------------------------------
# URL Resolution Helpers
# -------------------------------------------------------------------------
_resolve_url_deb() {
    local repo="$1" tag="$2"
	local suite=""
    local pkg_os=""
    local stable_path=""
    # Zabbix 7.2+ uses 'stable' URL structure (keep logic generic).
    if ver_ge_xy "$repo" "7.2"; then
        stable_path="/stable"
    fi
    #echo "https://repo.zabbix.com/zabbix/${repo}${stable_path}/ubuntu/pool/main/z/zabbix-release/zabbix-release_${repo}-1+ubuntu${tag}_all.deb"
	# Use the correct repository layout for Debian vs Ubuntu.
    case "$DISTRO_ID" in
        ubuntu) suite="ubuntu"; pkg_os="ubuntu${tag}" ;;
        debian) suite="debian"; pkg_os="debian${tag}" ;;
        *) die "Unsupported Debian-family distro for .deb resolver: ${DISTRO_ID}" ;;
    esac
    echo "https://repo.zabbix.com/zabbix/${repo}${stable_path}/${suite}/pool/main/z/zabbix-release/zabbix-release_${repo}-1+${pkg_os}_all.deb"
}

_resolve_url_rpm() {
    local repo="$1" tag="$2"

    # Candidate arch dirs to probe for zabbix-release package (it is usually noarch, but not guaranteed)
    local -a dirs=("noarch" "x86_64" "aarch64" "i386")

    local root arch
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue

        for arch in "${dirs[@]}"; do
            local base="${root}/${arch}"

            # Does directory exist?
            if curl "${CURL_OPTS[@]}" --connect-timeout 10 -fsIL "${base}/" >/dev/null 2>&1; then
                local listing
                listing="$(curl "${CURL_OPTS[@]}" --connect-timeout 10 -fsSL "${base}/" 2>/dev/null || true)"
                [[ -z "$listing" ]] && continue

                # Prefer "latest" if present (most predictable, no sorting required)
                local latest=""
                latest="$(printf '%s\n' "$listing" \
                    | grep -oE "zabbix-release-latest[^\"[:space:]]*\.${tag}\.noarch\.rpm" \
                    | head -n 1 || true)"

                if [[ -n "$latest" ]]; then
                    echo "${base}/${latest}"
                    return 0
                fi

                # Fallback: pick highest numeric release for zabbix-release-${repo}-N.*.${tag}.noarch.rpm
                local best_file="" best_rel=0
                local f rel
                while IFS= read -r f; do
                    [[ -z "$f" ]] && continue
                    rel="$(printf '%s' "$f" | sed -nE "s/^zabbix-release-${repo}-([0-9]+).*\.${tag}\.noarch\.rpm$/\1/p")"
                    [[ -z "$rel" ]] && continue
                    if (( rel > best_rel )); then
                        best_rel="$rel"
                        best_file="$f"
                    fi
                done < <(printf '%s\n' "$listing" \
                    | grep -oE "zabbix-release-${repo}-[0-9]+[^\"[:space:]]*\.${tag}\.noarch\.rpm" \
                    | sort -u)

                if [[ -n "$best_file" ]]; then
                    echo "${base}/${best_file}"
                    return 0
                fi
            fi
        done
    done < <(rpm_repo_root_candidates "$repo")

    log "No valid zabbix-release package found for repo=$repo and tag=$tag in any known RPM layout."
    return 1
}

resolve_release_pkg_url() {
    local repo="$1" tag="$2"
    local url=""

    if is_deb; then
        url="$(_resolve_url_deb "$repo" "$tag")"
    elif is_rpm; then
        url="$(_resolve_url_rpm "$repo" "$tag")"
    else
        log "No URL resolver available for this OS family." >&2
        return 1
    fi

    if [[ -n "$url" ]] && curl "${CURL_OPTS[@]}" --connect-timeout 15 -fsIL "$url" >/dev/null 2>&1; then
        echo "$url"
        return 0
    else
        log "URL not found or inaccessible for repo $repo / tag $tag" >&2
        return 1
    fi
}

zbx_repo_host() {
    # ZBX_BASE_URL_RPM is ".../zabbix" (or http://.../zabbix)
    echo "${ZBX_BASE_URL_RPM%/zabbix}"
}

pick_rpm_repo_root() {
    # Echo a root like: https://repo.zabbix.com/zabbix/<branch>/<release|stable>/<osdir>/<major>
    # Verified by probing for a plausible arch directory.
    local repo_branch="$1"
    local -a probe_arches=("x86_64" "aarch64" "i386")
    local root arch

    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        for arch in "${probe_arches[@]}"; do
            if curl "${CURL_OPTS[@]}" --connect-timeout 10 -fsIL "${root}/${arch}/" >/dev/null 2>&1; then
                echo "$root"
                return 0
            fi
        done
    done < <(rpm_repo_root_candidates "$repo_branch")

    return 1
}

pick_rpm_nonsupported_root() {
    # Best-effort: non-supported historically is under /non-supported/<osdir>/<major>/<arch>/
    local ns_base
    ns_base="$(zbx_repo_host)/non-supported"

    local osdir="${RPM_OSDIR}"
    local maj="${RPM_MAJOR}"

    local -a osdirs=("$osdir")
    if [[ "$osdir" != "rhel" ]]; then osdirs+=("rhel"); fi
    if [[ "${REPO_TAG}" == el* ]]; then
        osdirs+=("centos" "rocky" "alma" "oracle")
    fi

    local -a probe_arches=("x86_64" "aarch64" "i386")
    local o arch

    for o in "${osdirs[@]}"; do
        for arch in "${probe_arches[@]}"; do
            if curl "${CURL_OPTS[@]}" --connect-timeout 10 -fsIL "${ns_base}/${o}/${maj}/${arch}/" >/dev/null 2>&1; then
                echo "${ns_base}/${o}/${maj}"
                return 0
            fi
        done
    done

    return 1
}

# -------------------------------------------------------------------------
# RPM Repo File Creation Fallback (aarch64 etc.)
# -------------------------------------------------------------------------
_create_repo_file_rpm() {
    local repo_branch="$1"
    local repo_file="/etc/yum.repos.d/zabbix.repo"

    log "Creating Zabbix repo file manually at $repo_file"

    # Determine gpg behavior
    local gpgcheck_val="1"
    if [[ $NO_GPGCHECK -eq 1 ]]; then
        gpgcheck_val="0"
    fi

    local gpg_key_url="https://repo.zabbix.com/RPM-GPG-KEY-ZABBIX-A14FE591"
    local gpg_key_file="/etc/pki/rpm-gpg/RPM-GPG-KEY-ZABBIX-A14FE591"

    execute mkdir -p /etc/pki/rpm-gpg
    execute curl "${CURL_OPTS[@]}" --connect-timeout 15 -fsSL "$gpg_key_url" -o "$gpg_key_file"

    # Pick base roots dynamically (supports /release, /stable, legacy; supports osdir variations)
    local root
    root="$(pick_rpm_repo_root "$repo_branch" || true)"
    [[ -n "$root" ]] || die "Could not determine a valid RPM repo root for branch ${repo_branch} (osdir=${RPM_OSDIR}, major=${RPM_MAJOR})."

    local ns_root=""
    ns_root="$(pick_rpm_nonsupported_root || true)"

    # Insecure repo option line (only when enabled)
    local ssl_line=""
    if [[ $INSECURE -eq 1 ]]; then
        ssl_line="sslverify=0"
    fi

    # Write repo file
    execute tee "$repo_file" > /dev/null <<-EOF
[zabbix]
name=Zabbix Official Repository - \$basearch
baseurl=${root}/\$basearch/
enabled=1
gpgcheck=${gpgcheck_val}
gpgkey=file://${gpg_key_file}
${ssl_line}

EOF

    if [[ -n "$ns_root" ]]; then
        execute tee -a "$repo_file" > /dev/null <<-EOF
[zabbix-non-supported]
name=Zabbix Official Repository non-supported - \$basearch
baseurl=${ns_root}/\$basearch/
enabled=1
gpgcheck=${gpgcheck_val}
gpgkey=file://${gpg_key_file}
${ssl_line}

EOF
    else
        warn "Non-supported repo root not found (best-effort). Skipping [zabbix-non-supported] section."
    fi
}

proc_running() {
    # Usage: proc_running <name>
    local name="$1"
    if have pgrep; then
        pgrep -x "$name" >/dev/null 2>&1 && return 0
        return 1
    fi
    # Fallback: ps output varies; this is best-effort.
    ps ax 2>/dev/null | grep -E "[[:space:]]${name}([[:space:]]|$)" >/dev/null 2>&1 && return 0
    return 1
}

rpm_lock_busy() {
    # Prefer fuser, fallback to lsof, else "unknown" => assume not busy.
    if have fuser; then
        fuser /var/lib/rpm/.rpm.lock >/dev/null 2>&1 && return 0
        return 1
    fi
    if have lsof; then
        lsof /var/lib/rpm/.rpm.lock >/dev/null 2>&1 && return 0
        return 1
    fi
    return 1
}

# -------------------------------------------------------------------------
# Wait for dnf/yum Lock
# -------------------------------------------------------------------------
wait_for_dnf_lock() {
    local retries=30 # ~5 min timeout
    [[ $DRY_RUN -eq 1 ]] && return 0

    if ! is_rpm; then
        return 0
    fi

    log "Checking for dnf/yum activity..."

    while proc_running dnf || proc_running yum || rpm_lock_busy; do
        ((retries--)) || die "Timeout waiting for dnf/yum to finish"

        local dnf_pids
        local yum_pids
        local rpm_pids
		
        if have pgrep; then
            dnf_pids="$(pgrep -x dnf 2>/dev/null || true)"
            yum_pids="$(pgrep -x yum 2>/dev/null || true)"
        else
            dnf_pids=""
            yum_pids=""
        fi

        if have fuser; then
            rpm_pids="$(fuser /var/lib/rpm/.rpm.lock 2>/dev/null || true)"
        else
            rpm_pids=""
        fi

        if [[ -n "$dnf_pids$yum_pids$rpm_pids" ]]; then
            warn "Blocking processes detected:"
            [[ -n "$dnf_pids" ]] && ps -fp $dnf_pids || true
            [[ -n "$yum_pids" ]] && ps -fp $yum_pids || true
            [[ -n "$rpm_pids" ]] && ps -fp $rpm_pids || true
        fi

        warn "dnf/yum is running or RPM DB is locked. Waiting 10 seconds..."
        sleep 10
    done

    log "dnf/yum lock is free and no active process detected."
}

# -------------------------------------------------------------------------
# Service Management (systemd + legacy service/chkconfig)
# -------------------------------------------------------------------------
enable_service() {
    local svc="$1"
    if have systemctl; then
        execute systemctl enable "$svc"
    elif have chkconfig; then
        execute chkconfig "$svc" on || true
    else
        warn "No init system detected to enable '$svc' at boot."
    fi
}

restart_service() {
    local svc="$1"
    if have systemctl; then
        execute systemctl restart "$svc"
    elif have service; then
        execute service "$svc" restart
    else
        warn "No systemctl or service command found to restart '$svc'. Please restart it manually."
    fi
}

get_service_state() {
    local svc="$1"
    local state="<unknown>"

    if have systemctl; then
        if systemctl is-active --quiet "$svc"; then
            state="active (running)"
        else
            state="$(systemctl is-active "$svc" 2>/dev/null || echo 'inactive')"
        fi
    elif have service; then
        state="$(service "$svc" status 2>/dev/null | grep -Eo 'running|stopped' | head -1 || echo 'unknown')"
    else
        state="<unknown>"
    fi

    printf "%s" "$state"
}

get_service_enabled() {
    local svc="$1"
    local enabled="<unknown>"

    if have systemctl; then
        if systemctl is-enabled --quiet "$svc"; then
            enabled="enabled"
        else
            enabled="$(systemctl is-enabled "$svc" 2>/dev/null || echo 'disabled')"
        fi
    elif have chkconfig; then
        if chkconfig --list "$svc" 2>/dev/null | grep -q ':on'; then
            enabled="enabled"
        else
            enabled="disabled"
        fi
    else
        enabled="<n/a>"
    fi

    printf "%s" "$enabled"
}

# -------------------------------------------------------------------------
# Package Version Helpers
# -------------------------------------------------------------------------
get_installed_version() {
    local pkg="$1"
    local ver=""

    if is_deb; then
        ver="$(dpkg -s "$pkg" 2>/dev/null | awk '/^Version:/ {print $2}' || true)"
    elif is_rpm; then
        ver="$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$pkg" 2>/dev/null || true)"
        if [[ "$ver" == "package ${pkg} is not installed" ]]; then
            ver=""
        fi
    fi

    printf "%s" "$ver"
}

get_candidate_version() {
    local pkg="$1"
    local cand=""

    if is_deb; then
        cand="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}' || true)"
    elif is_rpm; then
        if have dnf; then
			cand="$(dnf -q list --available "$pkg" 2>/dev/null | awk -v p="$pkg" '$1 ~ "^"p"([.]|$)" {print $2; exit}' || true)"
        elif have yum; then
			cand="$(yum -q list available "$pkg" 2>/dev/null | awk -v p="$pkg" '$1 ~ "^"p"([.]|$)" {print $2; exit}' || true)"
        fi
    fi

    printf "%s" "$cand"
}

# Detect existing Zabbix branch (ex.: 5.0, 6.0, 7.0) a partir do agente instalado
detect_existing_repo_branch() {
    local v branch

    v="$(get_installed_version zabbix-agent2)"
    if [[ -n "$v" ]]; then
        v="${v#*:}"
        v="${v%%-*}"
        branch="$(printf '%s\n' "$v" | awk -F. '{print $1"."$2}')"
        if [[ -n "$branch" ]]; then
            printf '%s\n' "$branch"
            return 0
        fi
    fi

    v="$(get_installed_version zabbix-agent)"
    if [[ -n "$v" ]]; then
        v="${v#*:}"
        v="${v%%-*}"
        branch="$(printf '%s\n' "$v" | awk -F. '{print $1"."$2}')"
        if [[ -n "$branch" ]]; then
            printf '%s\n' "$branch"
            return 0
        fi
    fi

    return 1
}

# Instala pacotes Zabbix diretamente via rpm (fallback para EL5 com yum quebrado)
install_zbx_rpm_direct() {
    local pkg="$1"
    local maj="${REPO_TAG#el}"

    local dirs=(
        "x86_64"
        "i386"
        "noarch"
    )

    local base=""
    local rpm_name=""

    for d in "${dirs[@]}"; do
        local candidate_base="${ZBX_BASE_URL_RPM}/${REPO_BRANCH}/rhel/${maj}/${d}"

        if ! curl "${CURL_OPTS[@]}" --connect-timeout 10 -fsIL "${candidate_base}/" >/dev/null 2>&1; then
            continue
        fi

        local listing
        listing="$(curl "${CURL_OPTS[@]}" -s "${candidate_base}/" || true)"
        if [[ -z "$listing" ]]; then
            continue
        fi

        local name
        name="$(printf '%s\n' "$listing" \
            | grep -oE "${pkg}-[0-9][0-9A-Za-z_.-]*\.${d}\.rpm" \
            | sort -V \
            | tail -1 || true)"

        if [[ -n "$name" ]]; then
            base="$candidate_base"
            rpm_name="$name"
            break
        fi
    done

    if [[ -z "$rpm_name" ]]; then
        die "Could not locate remote RPM for package '${pkg}' in Zabbix repo branch ${REPO_BRANCH} (tag ${REPO_TAG})."
    fi

    local tmp="/tmp/${rpm_name}"
    log "Downloading package '${pkg}' from ${base}/${rpm_name}..."
    execute curl "${CURL_OPTS[@]}" --connect-timeout 20 -fsSL "${base}/${rpm_name}" -o "$tmp"

    log "Installing package '${pkg}' via rpm -Uvh..."
    execute rpm -Uvh --force "${RPM_NOGPG_ARGS[@]}" "$tmp"
}

# -------------------------------------------------------------------------
# Main Logic
# -------------------------------------------------------------------------
detect_os

# Choose HTTP for legacy RHEL5 due to old SSL stack
if is_rpm; then
    major="${DISTRO_VER%%.*}"
    if [[ ( "$DISTRO_ID" == "rhel" || "$DISTRO_ID" == "centos" || "$DISTRO_ID" == "ol" ) && "$major" -le 5 ]]; then
        ZBX_BASE_URL_RPM="http://repo.zabbix.com/zabbix"
        log "Legacy RHEL-like (${DISTRO_VER}) detected. Using HTTP for Zabbix RPM repo."
    fi
fi

# ------------------ V1 Agent Cleanup Logic ------------------
if have zabbix_agentd; then
    if [[ $CLEANUP_V1 -eq 1 ]]; then
        log "Classic zabbix-agent (v1) found. Proceeding with removal as requested by --cleanup-v1-agent flag."

        if is_deb; then
            log "Detected Debian-based system. Stopping zabbix-agent service..."
            if have systemctl; then
                execute_may_fail systemctl stop zabbix-agent
                execute_may_fail systemctl disable zabbix-agent
            elif have service; then
                execute_may_fail service zabbix-agent stop
            fi
            log "Purging zabbix-agent package (best-effort)..."
            execute_may_fail apt-get -y purge zabbix-agent

        elif is_rpm; then
            log "Detected RPM-based system. Checking dnf/yum lock and stopping service..."
            wait_for_dnf_lock

            if have systemctl; then
                execute_may_fail systemctl stop zabbix-agent
                execute_may_fail systemctl disable zabbix-agent
            elif have service; then
                execute_may_fail service zabbix-agent stop
            fi

            log "Removing zabbix-agent package via rpm (not using yum/dnf)..."
            if rpm -q zabbix-agent >/dev/null 2>&1; then
                execute_may_fail rpm -e zabbix-agent
            else
                log "Package 'zabbix-agent' is not installed (nothing to remove)."
            fi
        fi

        log "Classic zabbix-agent (v1) cleanup phase completed (check warnings above, if any)."
    else
        warn "Classic zabbix-agent (v1) is installed. This script manages both agent1 and agent2."
        warn "Coexistence of two agents is not recommended. Use --cleanup-v1-agent to remove v1 before install."
    fi
fi

# ------------------ Repository Resolution ------------------
REPO_TAG="$(map_repo_tag "$DISTRO_ID" "$DISTRO_VER")"
if is_rpm; then
    init_rpm_repo_context
fi

# Exemplo de checagem explícita de compatibilidade forçada
if [[ "$REPO_TAG" == "el8" && "$REPO_OVERRIDE" == "6.0" ]]; then
    die "Zabbix 6.0 is no longer available for EL8. Please migrate to EL9 or build from source."
fi

REPO_URL=""
EXISTING_BRANCH=""

# Se o usuário não forçou --repo, tentar preservar o branch atual do agente (se existir)
if [[ -z "$REPO_OVERRIDE" ]]; then
    EXISTING_BRANCH="$(detect_existing_repo_branch || true)"
fi

if [[ -n "$REPO_OVERRIDE" ]]; then
    log "Attempting to use specified repo branch: $REPO_OVERRIDE"
    REPO_BRANCH="$REPO_OVERRIDE"
	
	log "Validating remote repository URL (this may take a moment)..."
    REPO_URL="$(resolve_release_pkg_url "$REPO_BRANCH" "$REPO_TAG" || true)"
	
elif [[ -n "$EXISTING_BRANCH" ]]; then
    REPO_BRANCH="$EXISTING_BRANCH"
    log "Existing Zabbix agent detected. Preserving repo branch: ${REPO_BRANCH}"
	
	log "Validating remote repository for existing branch (this may take a moment)..."
    REPO_URL="$(resolve_release_pkg_url "$REPO_BRANCH" "$REPO_TAG" || true)"
	
    if [[ -z "$REPO_URL" ]]; then
        warn "Could not resolve zabbix-release package for existing branch ${REPO_BRANCH} (tag ${REPO_TAG}). Falling back to automatic branch detection."
        REPO_BRANCH=""
    fi
fi

if [[ -z "$REPO_BRANCH" ]]; then
    log "Detecting appropriate Zabbix repo branch for this OS..."

    branches=()
    if [[ "$REPO_TAG" == "el5" ]]; then
        # Para RHEL5, manter branch 5.0 por padrão (Agent 1 - 5.0.x)
        branches=(5.0)
    else
        branches=(7.4 7.2 7.0 6.4 6.0 5.0)
    fi
	
	log "Scanning Zabbix mirrors for valid branches (this may take a while)..."
	
    for try in "${branches[@]}"; do
        if url="$(resolve_release_pkg_url "$try" "$REPO_TAG" 2>/dev/null || true)"; then
            if [[ -n "$url" ]]; then
                REPO_URL="$url"
                REPO_BRANCH="$try"
                break
            fi
        fi
    done
fi

if [[ -z "$REPO_BRANCH" ]]; then
    die "Could not resolve a valid Zabbix repo for distro=$DISTRO_ID tag=$REPO_TAG"
fi

if is_deb && [[ -z "$REPO_URL" ]]; then
    die "Could not resolve zabbix-release package (.deb) for repo=$REPO_BRANCH and tag=$REPO_TAG"
fi

log "Repo branch selected: $REPO_BRANCH"
[[ -n "$REPO_URL" ]] && log "Repo package URL: $REPO_URL"

# -------------------------------------------------------------------------
# Repository Installation
# -------------------------------------------------------------------------
REPO_WAS_INSTALLED=0

if is_deb; then
    if [[ -z "$REPO_URL" ]]; then
        die "Could not get a repo package URL for a Debian-based system."
    fi

    CURRENT_RELVER=""
    CURRENT_REPO_URL=""
    TMPFILE=""

    CURRENT_RELVER="$(dpkg -s zabbix-release 2>/dev/null | awk '/^Version:/ {print $2}' || true)"
    CURRENT_REPO_URL="$(grep -E '^deb' /etc/apt/sources.list.d/zabbix.list 2>/dev/null | head -1 | awk '{print $2}' || true)"

    if [[ -n "$CURRENT_RELVER" && "$CURRENT_REPO_URL" == *"/zabbix/${REPO_BRANCH}/"* ]]; then
        log "Existing Zabbix release (${CURRENT_RELVER}) is compatible with branch ${REPO_BRANCH}."
        log "Skipping repository reinstall."
    else
        log "Zabbix release missing or not matching branch ${REPO_BRANCH}. Proceeding with fresh installation."

        TMPFILE="/tmp/zbx-release.$$"
		cleanup_deb() { rm -f "$TMPFILE" 2>/dev/null || true; }
        trap cleanup_deb EXIT

        log "Downloading Debian package from $REPO_URL..."
        curl "${CURL_OPTS[@]}" --connect-timeout 15 -fsSL "$REPO_URL" -o "$TMPFILE" || die "Download of repository package failed."

        have dpkg || die "Command 'dpkg' not found."
        log "Removing old Zabbix repo definitions (if any)..."
        execute_may_fail apt-get -y purge zabbix-release
        execute rm -f /etc/apt/sources.list.d/zabbix*.list

        log "Installing Zabbix release package..."
        execute dpkg -i "$TMPFILE"
        REPO_WAS_INSTALLED=1
    fi

    if [[ "$REPO_WAS_INSTALLED" -eq 1 ]]; then
        log "Updating package lists after repository installation..."
        execute apt-get update
    else
        log "Repository already present. Skipping apt-get update."
    fi

elif is_rpm; then
    have rpm || die "Command 'rpm' not found."
    CURRENT_REPO_FILE="/etc/yum.repos.d/zabbix.repo"
    REPO_WAS_INSTALLED=0

    if [[ -f "$CURRENT_REPO_FILE" && "$(grep 'baseurl=' "$CURRENT_REPO_FILE" 2>/dev/null)" == *"/zabbix/${REPO_BRANCH}/"* ]]; then
        log "Existing Zabbix repo file is already configured for branch ${REPO_BRANCH}."
        log "Skipping zabbix-release reinstall."
		if [[ $INSECURE -eq 1 ]]; then
            log "Insecure mode enabled. Disabling SSL verification for Zabbix repo (sslverify=0)."
            sync_insecure_repo_settings_rpm
        fi
    else
        log "Local Zabbix repo definition missing or not matching branch ${REPO_BRANCH}. Preparing fresh zabbix-release installation."
        wait_for_dnf_lock

        if rpm -q zabbix-release >/dev/null 2>&1; then
            log "Removing old zabbix-release package via rpm (not using yum/dnf)..."
            execute_may_fail rpm -e zabbix-release
        fi

        execute rm -f /etc/yum.repos.d/zabbix*.repo
        REPO_WAS_INSTALLED=1
    fi

    if [[ $REPO_WAS_INSTALLED -eq 1 ]]; then
        if [[ -n "$REPO_URL" ]]; then
            TMPFILE="/tmp/zbx-release.$$"
            cleanup_rpm() { rm -f "$TMPFILE" 2>/dev/null || true; }
            trap cleanup_rpm EXIT

            log "Downloading RPM package from $REPO_URL..."
            curl "${CURL_OPTS[@]}" --connect-timeout 15 -fsSL "$REPO_URL" -o "$TMPFILE" || die "Download of repository package failed."

            log "Installing Zabbix release package via rpm..."
            wait_for_dnf_lock
            execute rpm -Uvh --force "${RPM_NOGPG_ARGS[@]}" "$TMPFILE"
			if [[ $INSECURE -eq 1 ]]; then
                log "Insecure mode enabled. Disabling SSL verification for Zabbix repo (sslverify=0)."
                sync_insecure_repo_settings_rpm
            fi
        elif [[ "$ARCH" == "aarch64" ]]; then
            warn "zabbix-release package not found for aarch64. Creating repo file manually as a fallback."
            _create_repo_file_rpm "$REPO_BRANCH"
			if [[ $INSECURE -eq 1 ]]; then
                log "Insecure mode enabled. Disabling SSL verification for Zabbix repo (sslverify=0)."
                sync_insecure_repo_settings_rpm
            fi
        else
            die "Repository URL could not be determined for this RPM-based system."
        fi
    else
        log "Repository already valid for branch ${REPO_BRANCH}. Skipping zabbix-release installation."
    fi

    if [[ $REPO_WAS_INSTALLED -eq 1 ]]; then
        log "Cleaning and updating package cache after repository installation (best effort)..."
        wait_for_dnf_lock
        if have dnf; then
            execute_may_fail dnf clean all
            execute_may_fail dnf makecache -y
        elif have yum; then
            execute_may_fail yum clean all
            execute_may_fail yum makecache -y
        fi
    else
        log "Repository already present. Skipping cache rebuild."
    fi
fi

# -------------------------------------------------------------------------
# Package Metadata Refresh (Best Effort)
# -------------------------------------------------------------------------
if is_rpm; then
    wait_for_dnf_lock
    if have dnf; then
        execute_may_fail dnf -y makecache --refresh
    elif have yum; then
        execute_may_fail yum -y makecache
    fi
fi

# -------------------------------------------------------------------------
# Agent Package Selection (Agent 1 vs Agent 2)
# -------------------------------------------------------------------------
AGENT_PKG=""
AGENT_TYPE=""   # "1" or "2"
CANDIDATE=""
INSTALLED=""
NEED_INSTALL=0

INSTALLED_V2="$(get_installed_version zabbix-agent2)"
INSTALLED_V1="$(get_installed_version zabbix-agent)"

case "$AGENT_FLAVOR" in
    2)
        AGENT_PKG="zabbix-agent2"
        AGENT_TYPE="2"
        INSTALLED="$INSTALLED_V2"
        if [[ -z "$INSTALLED" ]]; then
            NEED_INSTALL=1
        fi
        ;;
    1)
        AGENT_PKG="zabbix-agent"
        AGENT_TYPE="1"
        INSTALLED="$INSTALLED_V1"
        if [[ -z "$INSTALLED" ]]; then
            NEED_INSTALL=1
        fi
        ;;
    auto)
        if [[ -n "$INSTALLED_V2" ]]; then
            AGENT_PKG="zabbix-agent2"
            AGENT_TYPE="2"
            INSTALLED="$INSTALLED_V2"
            NEED_INSTALL=0
            log "Existing Zabbix Agent 2 detected. Will reuse installed package without changing version (unless --force)."
        elif [[ -n "$INSTALLED_V1" ]]; then
            AGENT_PKG="zabbix-agent"
            AGENT_TYPE="1"
            INSTALLED="$INSTALLED_V1"
            NEED_INSTALL=0
            log "Existing classic Zabbix Agent (v1) detected. Will reuse installed package without changing version (unless --force)."
        else
            # Nenhum agente instalado: preferir agent2 se disponível no repo
            CANDIDATE="$(get_candidate_version zabbix-agent2)"
            if [[ -n "$CANDIDATE" && "$CANDIDATE" != "(none)" && "$CANDIDATE" != "Available" ]]; then
                AGENT_PKG="zabbix-agent2"
                AGENT_TYPE="2"
                NEED_INSTALL=1
            else
                if [[ -n "$CANDIDATE" ]]; then
                    log "zabbix-agent2 candidate not valid or not available. Trying classic 'zabbix-agent'..."
                fi
                CANDIDATE="$(get_candidate_version zabbix-agent)"
                if [[ -n "$CANDIDATE" && "$CANDIDATE" != "(none)" && "$CANDIDATE" != "Available" ]]; then
                    AGENT_PKG="zabbix-agent"
                    AGENT_TYPE="1"
                    NEED_INSTALL=1
                    log "Falling back to classic Zabbix Agent (v1) package 'zabbix-agent'."
                else
                    die "No suitable Zabbix agent package found (neither zabbix-agent2 nor zabbix-agent) in repo ${REPO_BRANCH} (tag ${REPO_TAG})."
                fi
            fi
        fi
        ;;
esac

# Se for necessário instalar ou se --force foi pedido, buscar versão candidata do pacote selecionado
if [[ $NEED_INSTALL -eq 1 || $FORCE -eq 1 ]]; then
    if [[ -z "$CANDIDATE" ]]; then
        CANDIDATE="$(get_candidate_version "$AGENT_PKG")"
    fi
    if [[ -z "${CANDIDATE}" || "${CANDIDATE}" == "(none)" || "${CANDIDATE}" == "Available" ]]; then
        die "No candidate version found for ${AGENT_PKG} in repo ${REPO_BRANCH} (tag ${REPO_TAG})."
    fi
fi

log "Agent flavor selected: ${AGENT_TYPE:-<unknown>} (package: ${AGENT_PKG:-<none>})"
log "Installed version: ${INSTALLED:-(none)}"
[[ -n "$CANDIDATE" ]] && log "Candidate version: ${CANDIDATE}"

# -------------------------------------------------------------------------
# Agent Installation / Upgrade
# -------------------------------------------------------------------------
if [[ $NEED_INSTALL -eq 0 && $FORCE -eq 0 ]]; then
    log "Agent package '${AGENT_PKG}' already installed (version: ${INSTALLED:-<unknown>})."
    log "Skipping package installation/upgrade (use --force to reinstall/upgrade)."
else
    log "Installing/Updating ${AGENT_PKG}${CANDIDATE:+ to version $CANDIDATE}..."
    if is_deb; then
        execute apt-get install -y --allow-downgrades "$AGENT_PKG"
    else
        # RPM-based
        if [[ "$REPO_TAG" == "el5" ]]; then
            log "Legacy EL5 detected. Installing '${AGENT_PKG}' directly via rpm (not using yum/dnf)."
            wait_for_dnf_lock
            install_zbx_rpm_direct "$AGENT_PKG"
        else
            wait_for_dnf_lock
            if have dnf; then
                execute dnf install -y "${PKG_NOGPGCHECK_ARGS[@]}" "$AGENT_PKG"
            elif have yum; then
                execute yum install -y "${PKG_NOGPGCHECK_ARGS[@]}" "$AGENT_PKG"
            else
                die "Neither dnf nor yum detected; cannot install ${AGENT_PKG}."
            fi
        fi
    fi
fi

# Instalação opcional de ferramentas (sempre best-effort)
if [[ $INSTALL_TOOLS -eq 1 ]]; then
    log "Installing Zabbix tools (zabbix-get, zabbix-sender)..."
    if is_deb; then
        execute_may_fail apt-get install -y zabbix-get zabbix-sender
    else
        wait_for_dnf_lock
        if have dnf; then
			execute_may_fail dnf install -y "${PKG_NOGPGCHECK_ARGS[@]}" zabbix-get zabbix-sender
        elif have yum; then
            execute_may_fail yum install -y "${PKG_NOGPGCHECK_ARGS[@]}" zabbix-get zabbix-sender
        else
            warn "Neither dnf nor yum detected; cannot install Zabbix tools."
        fi
    fi
fi

# -------------------------------------------------------------------------
# Config File Verification / Recovery
# -------------------------------------------------------------------------
CONF=""
SERVICE_NAME=""

if [[ "$AGENT_TYPE" == "2" ]]; then
    CONF="/etc/zabbix/zabbix_agent2.conf"
    SERVICE_NAME="zabbix-agent2"
else
    CONF="/etc/zabbix/zabbix_agentd.conf"
    SERVICE_NAME="zabbix-agent"
fi

if [[ ! -f "$CONF" ]]; then
    warn "Config file '$CONF' not found after initial install. Forcing a reinstall to restore missing files..."

    if is_deb; then
        execute apt-get -o Dpkg::Options::="--force-confmiss" install --reinstall -y "$AGENT_PKG"
    elif is_rpm; then
        if [[ "$REPO_TAG" == "el5" ]]; then
            log "Legacy EL5 + missing config: reinstalling '${AGENT_PKG}' via rpm fallback..."
            wait_for_dnf_lock
            install_zbx_rpm_direct "$AGENT_PKG"
        else
            wait_for_dnf_lock
            if have dnf; then
                execute dnf reinstall -y "${PKG_NOGPGCHECK_ARGS[@]}" "$AGENT_PKG"
            elif have yum; then
				execute yum reinstall -y "${PKG_NOGPGCHECK_ARGS[@]}" "$AGENT_PKG"
            else
                die "Neither dnf nor yum detected; cannot reinstall ${AGENT_PKG} to restore config."
            fi
        fi
    fi
fi

if [[ ! -f "$CONF" ]]; then
    die "Config file '$CONF' still not found after reinstall attempt. Please check the package integrity."
fi
log "Agent configuration file '$CONF' is present."

# -------------------------------------------------------------------------
# Agent Configuration
# -------------------------------------------------------------------------
log "Configuring agent ($AGENT_PKG)..."

run_silent sed -i \
    -e '/^#\?Server=/d' \
    -e '/^#\?ServerActive=/d' \
    -e '/^#\?Hostname=/d' \
    "$CONF"

run_silent bash -c "echo 'Server=${SERVER},127.0.0.1' >> '$CONF'"
if [[ -n "$ACTIVE" ]]; then
    run_silent bash -c "echo 'ServerActive=${ACTIVE}' >> '$CONF'"
fi

enable_service "$SERVICE_NAME"
restart_service "$SERVICE_NAME"

SERVICE_STATE="$(get_service_state "$SERVICE_NAME")"
SERVICE_ENABLED="$(get_service_enabled "$SERVICE_NAME")"

# -------------------------------------------------------------------------
# Final Report
# -------------------------------------------------------------------------
AGVER=""
if [[ $DRY_RUN -eq 0 ]]; then
    if [[ "$AGENT_TYPE" == "2" ]]; then
        if have zabbix_agent2; then
            AGVER="$(zabbix_agent2 -V 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        fi
    else
        if have zabbix_agentd; then
            AGVER="$(zabbix_agentd -V 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        fi
    fi
fi

RELVER=""
if is_deb; then
    RELVER="$(dpkg -s zabbix-release 2>/dev/null | awk '/^Version:/ {print $2}' || true)"
elif is_rpm; then
    RELVER="$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' zabbix-release 2>/dev/null || true)"
fi

printf "\n"
ok "Zabbix Agent installation process finished."
if [[ $DRY_RUN -eq 1 ]]; then
    printf "    NOTE: This was a dry run. No actual changes were made to the system.\n"
fi

printf "    %-18s: %s\n" "Repo Branch"      "$REPO_BRANCH${REPO_FALLBACK:+ ($REPO_FALLBACK)}"
printf "    %-18s: %s\n" "Repo Package"     "${RELVER:-<unknown>}"
printf "    %-18s: %s\n" "Agent Package"    "$AGENT_PKG"
printf "    %-18s: %s\n" "Agent Flavor"     "v${AGENT_TYPE}"
printf "    %-18s: %s\n" "Agent Version"    "${AGVER:-<unknown or not run>}"
printf "    %-18s: %s\n" "Config File"      "$CONF"
printf "    %-18s: %s\n" "Server"           "${SERVER},127.0.0.1"
printf "    %-18s: %s\n" "ServerActive"     "${ACTIVE:-<not set>}"
printf "    %-18s: %s\n" "Service Name"     "$SERVICE_NAME"
printf "    %-18s: %s\n" "Service Status"   "$SERVICE_STATE"
printf "    %-18s: %s\n" "Service Enabled"  "$SERVICE_ENABLED"
printf "    %-18s: %s\n" "Insecure Mode"   "$([[ $INSECURE -eq 1 ]] && echo enabled || echo disabled)"
printf "\n"

exit 0
