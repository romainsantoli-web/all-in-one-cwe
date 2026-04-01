#!/usr/bin/env bash
# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
# =============================================================================
# install-tools.sh — Unified installer for Security All-in-One CWE
# Installs ALL 70+ security tools in one shot: Docker images, Go/Rust binaries,
# Python packages, system tools, and git-cloned scanners.
#
# Usage:
#   ./scripts/install-tools.sh              # Install everything
#   ./scripts/install-tools.sh --docker     # Docker images only
#   ./scripts/install-tools.sh --native     # Native binaries only (no Docker)
#   ./scripts/install-tools.sh --check      # Verify what's installed
#   ./scripts/install-tools.sh --minimal    # Essential 15 tools only
# =============================================================================
set -euo pipefail

# ── Colors ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Globals ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools"
VENV_DIR="$PROJECT_ROOT/.venv"
INSTALL_LOG="$PROJECT_ROOT/.install-tools.log"
ERRORS=0
INSTALLED=0
SKIPPED=0

# ── Helpers ─────────────────────────────────────────────
log()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; ((ERRORS++)) || true; }
info()  { echo -e "${BLUE}[i]${NC} $*"; }
header(){ echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

has_cmd() { command -v "$1" &>/dev/null; }

check_or_install() {
    local name="$1" cmd="$2"
    if has_cmd "$cmd"; then
        log "$name already installed ($(command -v "$cmd"))"
        ((SKIPPED++)) || true
        return 1
    fi
    return 0
}

# ── Detect OS ───────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Darwin*) OS="macos" ;;
        Linux*)  OS="linux" ;;
        *)       err "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac
    ARCH="$(uname -m)"
    info "Detected: $OS / $ARCH"
}

# ── Prerequisites ───────────────────────────────────────
check_prerequisites() {
    header "Checking prerequisites"

    # Docker
    if has_cmd docker; then
        local dv
        dv=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
        log "Docker $dv"
    else
        warn "Docker not found — Docker-based tools will be skipped"
        warn "Install: https://docs.docker.com/get-docker/"
    fi

    # Go
    if has_cmd go; then
        log "Go $(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1)"
    else
        warn "Go not found — will try Homebrew/apt for Go tools"
    fi

    # Python 3
    if has_cmd python3; then
        log "Python $(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
    else
        err "Python 3 is required but not found"
        exit 1
    fi

    # pip
    if python3 -m pip --version &>/dev/null; then
        log "pip available"
    else
        err "pip not found — install with: python3 -m ensurepip"
        exit 1
    fi

    # Homebrew (macOS)
    if [[ "$OS" == "macos" ]]; then
        if has_cmd brew; then
            log "Homebrew $(brew --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        else
            warn "Homebrew not found — install: https://brew.sh"
        fi
    fi
}

# ═════════════════════════════════════════════════════════
# DOCKER IMAGES
# ═════════════════════════════════════════════════════════
install_docker_images() {
    header "Pulling Docker images (official)"

    if ! has_cmd docker; then
        warn "Docker not available — skipping all Docker images"
        return
    fi

    local images=(
        # ProjectDiscovery suite
        "projectdiscovery/nuclei:latest"
        "projectdiscovery/httpx:latest"
        "projectdiscovery/subfinder:latest"
        "projectdiscovery/naabu:latest"
        "projectdiscovery/katana:latest"
        "projectdiscovery/dnsx:latest"
        "projectdiscovery/interactsh-client:latest"
        # OWASP / Security
        "ghcr.io/zaproxy/zaproxy:stable"
        "semgrep/semgrep:latest"
        "ghcr.io/gitleaks/gitleaks:latest"
        "trufflesecurity/trufflehog:latest"
        "ghcr.io/aquasecurity/trivy:latest"
        "owasp/dependency-check:latest"
        "fkiecad/cwe_checker:latest"
        # Recon / Network
        "punksecurity/dnsreaper:latest"
        "drwetter/testssl.sh:latest"
        "instrumentisto/nmap:latest"
        "caffix/amass:latest"
        "ghcr.io/hahwul/dalfox:latest"
        # Container / API
        "goodwithtech/dockle:latest"
        "bridgecrew/checkov:latest"
        "mcr.microsoft.com/restlerfuzzer/restler:latest"
        # Brute / Proxy / Network
        "vanhauser/hydra:latest"
        "mitmproxy/mitmproxy:latest"
        "adguard/masscan:latest"
        # Orchestration
        "prefecthq/prefect:3-latest"
    )

    local total=${#images[@]}
    local i=0
    for img in "${images[@]}"; do
        ((i++)) || true
        info "[$i/$total] Pulling $img..."
        if docker pull "$img" >> "$INSTALL_LOG" 2>&1; then
            log "$img"
            ((INSTALLED++)) || true
        else
            err "Failed to pull $img"
        fi
    done

    # Build all docker-compose services
    info "Building custom Docker images (docker compose build)..."
    if (cd "$PROJECT_ROOT" && docker compose build --parallel >> "$INSTALL_LOG" 2>&1); then
        log "All custom Docker images built"
    else
        warn "Some Docker builds failed — check $INSTALL_LOG"
    fi
}

# ═════════════════════════════════════════════════════════
# GO TOOLS (via Homebrew or go install)
# ═════════════════════════════════════════════════════════
install_go_tools() {
    header "Installing Go-based tools"

    # Tools available via Homebrew tap (projectdiscovery)
    local brew_tools=(
        "nuclei"
        "httpx"
        "subfinder"
        "naabu"
        "katana"
        "dnsx"
        "interactsh"
    )

    # Tools via go install
    local go_tools=(
        "github.com/hahwul/dalfox/v2@latest:dalfox"
        "github.com/ffuf/ffuf/v2@latest:ffuf"
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest:crlfuzz"
        "github.com/BishopFox/jsluice/cmd/jsluice@latest:jsluice"
    )

    # Try Homebrew first (macOS + linuxbrew)
    if has_cmd brew; then
        for tool in "${brew_tools[@]}"; do
            if check_or_install "$tool" "$tool"; then
                info "Installing $tool via Homebrew..."
                if brew install "$tool" >> "$INSTALL_LOG" 2>&1; then
                    log "$tool installed via Homebrew"
                    ((INSTALLED++)) || true
                else
                    warn "$tool Homebrew install failed — trying go install..."
                    install_go_tool_fallback "$tool"
                fi
            fi
        done
    elif has_cmd go; then
        # Fallback: go install for ProjectDiscovery tools
        local pd_go_tools=(
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest:nuclei"
            "github.com/projectdiscovery/httpx/cmd/httpx@latest:httpx"
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest:subfinder"
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest:naabu"
            "github.com/projectdiscovery/katana/cmd/katana@latest:katana"
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest:dnsx"
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest:interactsh-client"
        )
        for entry in "${pd_go_tools[@]}"; do
            local pkg="${entry%%:*}"
            local cmd="${entry##*:}"
            if check_or_install "$cmd" "$cmd"; then
                info "Installing $cmd via go install..."
                if go install "$pkg" >> "$INSTALL_LOG" 2>&1; then
                    log "$cmd installed"
                    ((INSTALLED++)) || true
                else
                    err "Failed to install $cmd"
                fi
            fi
        done
    else
        warn "Neither Homebrew nor Go available — skipping Go tools"
        warn "Install Go: https://go.dev/dl/ or Homebrew: https://brew.sh"
    fi

    # Additional Go tools (always via go install)
    if has_cmd go; then
        for entry in "${go_tools[@]}"; do
            local pkg="${entry%%:*}"
            local cmd="${entry##*:}"
            if check_or_install "$cmd" "$cmd"; then
                info "Installing $cmd via go install..."
                if go install "$pkg" >> "$INSTALL_LOG" 2>&1; then
                    log "$cmd installed"
                    ((INSTALLED++)) || true
                else
                    err "Failed: go install $pkg"
                fi
            fi
        done
    fi

    # Gowitness (needs special build with CGO)
    if check_or_install "gowitness" "gowitness"; then
        if has_cmd go; then
            info "Installing gowitness (requires chromium)..."
            if go install github.com/sensepost/gowitness@latest >> "$INSTALL_LOG" 2>&1; then
                log "gowitness installed"
                ((INSTALLED++)) || true
            else
                warn "gowitness install failed (may need CGO + chromium headers)"
            fi
        fi
    fi
}

install_go_tool_fallback() {
    local tool="$1"
    if ! has_cmd go; then return 1; fi
    local pkg=""
    case "$tool" in
        nuclei)     pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        httpx)      pkg="github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
        subfinder)  pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
        naabu)      pkg="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" ;;
        katana)     pkg="github.com/projectdiscovery/katana/cmd/katana@latest" ;;
        dnsx)       pkg="github.com/projectdiscovery/dnsx/cmd/dnsx@latest" ;;
        interactsh) pkg="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" ;;
        *) return 1 ;;
    esac
    if go install "$pkg" >> "$INSTALL_LOG" 2>&1; then
        log "$tool installed via go install"
        ((INSTALLED++)) || true
    else
        err "Failed to install $tool via go install"
    fi
}

# ═════════════════════════════════════════════════════════
# RUST TOOLS
# ═════════════════════════════════════════════════════════
install_rust_tools() {
    header "Installing Rust-based tools"

    # Feroxbuster
    if check_or_install "feroxbuster" "feroxbuster"; then
        if has_cmd brew; then
            info "Installing feroxbuster via Homebrew..."
            if brew install feroxbuster >> "$INSTALL_LOG" 2>&1; then
                log "feroxbuster installed"
                ((INSTALLED++)) || true
                return
            fi
        fi
        if has_cmd cargo; then
            info "Installing feroxbuster via cargo..."
            if cargo install feroxbuster >> "$INSTALL_LOG" 2>&1; then
                log "feroxbuster installed via cargo"
                ((INSTALLED++)) || true
            else
                err "Failed to install feroxbuster"
            fi
        else
            warn "Neither Homebrew nor Cargo available — skipping feroxbuster"
        fi
    fi
}

# ═════════════════════════════════════════════════════════
# PYTHON TOOLS (via pip in venv)
# ═════════════════════════════════════════════════════════
install_python_tools() {
    header "Installing Python-based tools"

    # Create/activate venv
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating Python virtual environment at $VENV_DIR ..."
        python3 -m venv "$VENV_DIR"
    fi
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    # Pip packages (official tools)
    local pip_packages=(
        "sqlmap"
        "arjun"
        "wafw00f"
        "subdominator"
        "cve-bin-tool"
        "semgrep"
        "wapiti3"
        "shodan"
        "commix"
    )

    info "Installing ${#pip_packages[@]} Python packages..."
    for pkg in "${pip_packages[@]}"; do
        if pip install --quiet "$pkg" >> "$INSTALL_LOG" 2>&1; then
            log "$pkg"
            ((INSTALLED++)) || true
        else
            err "Failed: pip install $pkg"
        fi
    done

    # Custom Python scanners dependencies
    local req_file="$TOOLS_DIR/python-scanners/requirements.txt"
    if [[ -f "$req_file" ]]; then
        info "Installing custom scanner dependencies..."
        if pip install --quiet -r "$req_file" >> "$INSTALL_LOG" 2>&1; then
            log "Custom scanner dependencies installed"
        else
            warn "Some scanner dependencies failed — check $INSTALL_LOG"
        fi
    fi

    deactivate 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════
# GIT-CLONED TOOLS
# ═════════════════════════════════════════════════════════
install_git_tools() {
    header "Installing git-cloned tools"

    local git_tools_dir="$TOOLS_DIR/third-party"
    mkdir -p "$git_tools_dir"

    # Format: "repo_url:dir_name:setup_cmd"
    local repos=(
        "https://github.com/vladko312/SSTImap.git:sstimap:pip install -r requirements.txt"
        "https://github.com/dolevf/graphw00f.git:graphw00f:"
        "https://github.com/initstring/cloud_enum.git:cloud_enum:pip install -r requirements.txt"
        "https://github.com/swisskyrepo/SSRFmap.git:ssrfmap:pip install -r requirements.txt"
        "https://github.com/fullhunt/log4j-scan.git:log4j-scan:pip install -r requirements.txt"
        "https://github.com/laramies/theHarvester.git:theharvester:pip install ."
        "https://github.com/nikitastupin/clairvoyance.git:clairvoyance:pip install ."
        "https://github.com/Tuhinshubhra/CMSeeK.git:cmseek:"
        "https://github.com/lanmaster53/recon-ng.git:recon-ng:pip install -r REQUIREMENTS"
        "https://github.com/defparam/smuggler.git:smuggler:"
        "https://github.com/Nefcore/CORScanner.git:corscanner:"
        "https://github.com/iamj0ker/bypass-403.git:bypass-403:"
        "https://github.com/ticarpi/jwt_tool.git:jwt_tool:pip install -r requirements.txt"
    )

    # Activate venv for installs that need pip
    [[ -d "$VENV_DIR" ]] && source "$VENV_DIR/bin/activate"

    for entry in "${repos[@]}"; do
        IFS=':' read -r url dir setup <<< "$entry"
        local target="$git_tools_dir/$dir"
        if [[ -d "$target/.git" ]]; then
            log "$dir already cloned — pulling latest..."
            (cd "$target" && git pull --quiet >> "$INSTALL_LOG" 2>&1) || true
            ((SKIPPED++)) || true
        else
            info "Cloning $dir..."
            if git clone --depth 1 "$url" "$target" >> "$INSTALL_LOG" 2>&1; then
                log "$dir cloned"
                ((INSTALLED++)) || true
                # Run setup if specified
                if [[ -n "$setup" ]]; then
                    info "  Setting up $dir..."
                    (cd "$target" && eval "$setup" >> "$INSTALL_LOG" 2>&1) || warn "  Setup for $dir had issues"
                fi
            else
                err "Failed to clone $dir"
            fi
        fi
    done

    deactivate 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════
# SYSTEM TOOLS (nmap, nikto, testssl, whatweb, etc.)
# ═════════════════════════════════════════════════════════
install_system_tools() {
    header "Installing system tools"

    if [[ "$OS" == "macos" ]] && has_cmd brew; then
        local brew_pkgs=("nmap" "nikto" "testssl")
        for pkg in "${brew_pkgs[@]}"; do
            if check_or_install "$pkg" "$pkg"; then
                info "Installing $pkg via Homebrew..."
                if brew install "$pkg" >> "$INSTALL_LOG" 2>&1; then
                    log "$pkg installed"
                    ((INSTALLED++)) || true
                else
                    err "Failed: brew install $pkg"
                fi
            fi
        done

        # WhatWeb (Ruby-based)
        if check_or_install "whatweb" "whatweb"; then
            info "Installing whatweb via Homebrew..."
            if brew install whatweb >> "$INSTALL_LOG" 2>&1; then
                log "whatweb installed"
                ((INSTALLED++)) || true
            else
                warn "whatweb not in Homebrew — will use Docker version"
            fi
        fi

    elif [[ "$OS" == "linux" ]]; then
        if has_cmd apt-get; then
            info "Installing system packages via apt..."
            sudo apt-get update -qq >> "$INSTALL_LOG" 2>&1
            local apt_pkgs=("nmap" "nikto" "testssl.sh" "ruby" "perl" "libnet-ssleay-perl")
            for pkg in "${apt_pkgs[@]}"; do
                if sudo apt-get install -y -qq "$pkg" >> "$INSTALL_LOG" 2>&1; then
                    log "$pkg installed"
                    ((INSTALLED++)) || true
                else
                    warn "Failed: apt install $pkg"
                fi
            done
        else
            warn "apt-get not available — install nmap, nikto, testssl manually"
        fi
    fi

    # Node.js tools (RetireJS)
    if has_cmd npm; then
        if check_or_install "retire" "retire"; then
            info "Installing retire (RetireJS) via npm..."
            if npm install -g retire >> "$INSTALL_LOG" 2>&1; then
                log "retire installed"
                ((INSTALLED++)) || true
            else
                err "Failed: npm install -g retire"
            fi
        fi
    else
        warn "npm not found — skipping RetireJS"
    fi
}

# ═════════════════════════════════════════════════════════
# REPORT DIRECTORIES
# ═════════════════════════════════════════════════════════
create_report_dirs() {
    header "Creating report directories"

    local dirs=(
        nuclei zap sqlmap sstimap dnsreaper subdominator httpx subfinder naabu katana
        wafw00f bypass-403 ffuf feroxbuster arjun testssl corscanner nmap whatweb
        graphw00f cloud-enum dalfox interactsh nikto jwt-tool amass jsluice dnsx
        gowitness crlfuzz ssrfmap dockle retirejs log4j-scan theharvester cherrybomb
        ppmap clairvoyance cmseek gitleaks trufflehog trivy dependency-check semgrep
        cwe-checker cve-bin-tool garak
        idor-scanner auth-bypass user-enum notif-inject redirect-cors oidc-audit
        bypass-403-advanced ssrf-scanner xss-scanner api-discovery secret-leak
        websocket-scanner cache-deception slowloris-check waf-bypass source-map-scanner
        hidden-endpoint-scanner hateoas-fuzzer coupon-promo-fuzzer response-pii-detector
        header-classifier header-poc-generator timing-oracle oauth-flow-scanner
        cdp-token-extractor cdp-checkout-interceptor cdp-credential-scanner
        brute-forcer osint-enricher smuggler checkov restler hydra mitmproxy
        masscan recon-ng shodan commix wapiti searchsploit
        unified
    )

    for d in "${dirs[@]}"; do
        mkdir -p "$PROJECT_ROOT/reports/$d"
    done
    log "Created ${#dirs[@]} report directories"
}

# ═════════════════════════════════════════════════════════
# VERIFY INSTALLATION
# ═════════════════════════════════════════════════════════
verify_installation() {
    header "Verifying installation"

    local checks=(
        "nuclei:nuclei"
        "httpx:httpx"
        "subfinder:subfinder"
        "katana:katana"
        "naabu:naabu"
        "dnsx:dnsx"
        "dalfox:dalfox"
        "ffuf:ffuf"
        "feroxbuster:feroxbuster"
        "crlfuzz:crlfuzz"
        "gowitness:gowitness"
        "jsluice:jsluice"
        "nmap:nmap"
        "nikto:nikto"
        "testssl:testssl"
        "sqlmap:sqlmap"
        "arjun:arjun"
        "wafw00f:wafw00f"
        "semgrep:semgrep"
        "retire:retire"
        "whatweb:whatweb"
        "docker:docker"
    )

    local ok=0 missing=0
    echo ""
    printf "  %-20s %-10s %s\n" "TOOL" "STATUS" "PATH"
    printf "  %-20s %-10s %s\n" "────" "──────" "────"

    for entry in "${checks[@]}"; do
        local name="${entry%%:*}"
        local cmd="${entry##*:}"
        if has_cmd "$cmd"; then
            printf "  %-20s ${GREEN}%-10s${NC} %s\n" "$name" "✓" "$(command -v "$cmd")"
            ((ok++)) || true
        else
            printf "  %-20s ${RED}%-10s${NC} %s\n" "$name" "✗" "(not found)"
            ((missing++)) || true
        fi
    done

    # Check Docker images
    if has_cmd docker; then
        echo ""
        local docker_images
        docker_images=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -cE '(projectdiscovery|zaproxy|semgrep|gitleaks|trufflehog|trivy|cwe_checker|dnsreaper|testssl|nmap|dalfox|amass|dockle|checkov|hydra|mitmproxy|masscan)' || echo "0")
        info "Docker images available: $docker_images / 26 expected"
    fi

    echo ""
    info "Native tools: $ok installed, $missing missing"
}

# ═════════════════════════════════════════════════════════
# MINIMAL INSTALL (15 essential tools)
# ═════════════════════════════════════════════════════════
install_minimal() {
    header "Minimal install — 15 essential tools"

    # Docker: pull only essential images
    if has_cmd docker; then
        local essential_images=(
            "projectdiscovery/nuclei:latest"
            "projectdiscovery/httpx:latest"
            "projectdiscovery/subfinder:latest"
            "projectdiscovery/katana:latest"
            "ghcr.io/zaproxy/zaproxy:stable"
            "semgrep/semgrep:latest"
            "ghcr.io/gitleaks/gitleaks:latest"
            "ghcr.io/aquasecurity/trivy:latest"
        )
        for img in "${essential_images[@]}"; do
            info "Pulling $img..."
            docker pull "$img" >> "$INSTALL_LOG" 2>&1 && log "$img" || err "Failed: $img"
        done
    fi

    # Native: install the core recon tools
    if has_cmd brew; then
        for tool in nuclei httpx subfinder katana nmap testssl feroxbuster; do
            if check_or_install "$tool" "$tool"; then
                brew install "$tool" >> "$INSTALL_LOG" 2>&1 && log "$tool" || true
            fi
        done
    fi

    # Python essentials
    [[ ! -d "$VENV_DIR" ]] && python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install --quiet sqlmap semgrep wafw00f >> "$INSTALL_LOG" 2>&1
    log "Python essentials installed (sqlmap, semgrep, wafw00f)"
    deactivate 2>/dev/null || true

    create_report_dirs
    verify_installation
}

# ═════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   Security All-in-One CWE — Tool Installer                 ║"
    echo "║   70+ security tools • Docker + Native + Python            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    : > "$INSTALL_LOG"
    detect_os

    local mode="${1:-all}"

    case "$mode" in
        --check|-c)
            verify_installation
            exit 0
            ;;
        --minimal|-m)
            check_prerequisites
            install_minimal
            ;;
        --docker|-d)
            check_prerequisites
            install_docker_images
            create_report_dirs
            ;;
        --native|-n)
            check_prerequisites
            install_go_tools
            install_rust_tools
            install_python_tools
            install_git_tools
            install_system_tools
            create_report_dirs
            verify_installation
            ;;
        all|--all|-a|"")
            check_prerequisites
            install_docker_images
            install_go_tools
            install_rust_tools
            install_python_tools
            install_git_tools
            install_system_tools
            create_report_dirs
            verify_installation
            ;;
        --help|-h)
            echo "Usage: $0 [--all|--docker|--native|--minimal|--check|--help]"
            echo ""
            echo "  --all, -a      Install everything (default)"
            echo "  --docker, -d   Docker images only (pull + build)"
            echo "  --native, -n   Native binaries only (Go, Rust, Python, system)"
            echo "  --minimal, -m  Essential 15 tools only (fast)"
            echo "  --check, -c    Verify what's installed"
            echo "  --help, -h     Show this help"
            exit 0
            ;;
        *)
            err "Unknown option: $mode"
            echo "Run $0 --help for usage"
            exit 1
            ;;
    esac

    # Summary
    echo ""
    header "Installation Summary"
    log "Installed: $INSTALLED"
    info "Skipped (already present): $SKIPPED"
    if [[ $ERRORS -gt 0 ]]; then
        err "Errors: $ERRORS — check $INSTALL_LOG for details"
    else
        log "All tools installed successfully!"
    fi
    echo ""
    info "Next steps:"
    echo "  1. Run: make check       # Verify tools"
    echo "  2. Run: make run TARGET=https://target.example.com"
    echo "  3. Run: make dashboard   # View results"
    echo ""
}

main "$@"
