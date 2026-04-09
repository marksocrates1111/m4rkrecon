#!/bin/bash
#
# M4rkRecon v2.0.0 - Auto Installer
# Installs all required tools for the full reconnaissance pipeline.
# Run as root on a fresh VPS (Ubuntu/Debian/Kali recommended).
#
# Usage: chmod +x install.sh && sudo ./install.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${CYAN}"
echo "  ┌──────────────────────────────────────────┐"
echo "  │     M4rkRecon v2.0.0 - Auto Installer    │"
echo "  │        35+ Security Tools Setup           │"
echo "  └──────────────────────────────────────────┘"
echo -e "${NC}"

INSTALL_LOG="/tmp/m4rkrecon_install.log"
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="$(cd "$(dirname "$0")" && pwd)/wordlists"

mkdir -p "$TOOLS_DIR" "$WORDLIST_DIR"

success() { echo -e "  ${GREEN}[+]${NC} $1"; }
info()    { echo -e "  ${CYAN}[*]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "  ${RED}[-]${NC} $1"; }

install_tool() {
    local name="$1"
    local cmd="$2"
    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi
    info "Installing $name..."
    if eval "$cmd" >> "$INSTALL_LOG" 2>&1; then
        success "$name installed"
    else
        fail "$name installation failed (check $INSTALL_LOG)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Step 1: System dependencies
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 1/6] System Dependencies${NC}"

if command -v apt-get &>/dev/null; then
    info "Updating apt packages..."
    apt-get update -qq >> "$INSTALL_LOG" 2>&1
    apt-get install -y -qq \
        git curl wget unzip jq python3 python3-pip python3-venv \
        nmap masscan sslscan whois dnsutils \
        libpcap-dev build-essential >> "$INSTALL_LOG" 2>&1
    success "System packages installed"
elif command -v yum &>/dev/null; then
    info "Installing via yum..."
    yum install -y -q \
        git curl wget unzip jq python3 python3-pip \
        nmap sslscan whois bind-utils \
        libpcap-devel gcc >> "$INSTALL_LOG" 2>&1
    success "System packages installed"
else
    warn "Unknown package manager - install dependencies manually"
fi

# ──────────────────────────────────────────────────────────────
# Step 2: Go installation
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 2/6] Go Language${NC}"

if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}')
    success "Go already installed ($GO_VER)"
else
    info "Installing Go 1.23..."
    wget -q "https://go.dev/dl/go1.23.0.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    # Set up PATH
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.profile
    success "Go installed"
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

# ──────────────────────────────────────────────────────────────
# Step 3: Go-based tools (ProjectDiscovery + others)
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 3/6] Go-based Security Tools${NC}"

# ProjectDiscovery tools
install_tool "subfinder"    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_tool "httpx"        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_tool "nuclei"       "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_tool "naabu"        "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_tool "katana"       "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
install_tool "dnsx"         "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_tool "shuffledns"   "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
install_tool "tlsx"         "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"

# Other Go tools
install_tool "amass"        "go install -v github.com/owasp-amass/amass/v4/...@master"
install_tool "assetfinder"  "go install -v github.com/tomnomnom/assetfinder@latest"
install_tool "waybackurls"  "go install -v github.com/tomnomnom/waybackurls@latest"
install_tool "gau"          "go install -v github.com/lc/gau/v2/cmd/gau@latest"
install_tool "ffuf"         "go install -v github.com/ffuf/ffuf/v2@latest"
install_tool "gobuster"     "go install -v github.com/OJ/gobuster/v3@latest"
install_tool "dalfox"       "go install -v github.com/hahwul/dalfox/v2@latest"
install_tool "kxss"         "go install -v github.com/Emoe/kxss@latest"
install_tool "qsreplace"   "go install -v github.com/tomnomnom/qsreplace@latest"
install_tool "subjack"      "go install -v github.com/haccer/subjack@latest"
install_tool "subzy"        "go install -v github.com/PentestPad/subzy@latest"

# Update nuclei templates
info "Updating nuclei templates..."
nuclei -update-templates >> "$INSTALL_LOG" 2>&1 || true
success "Nuclei templates updated"

# ──────────────────────────────────────────────────────────────
# Step 4: Python-based tools
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 4/6] Python-based Security Tools${NC}"

# Install M4rkRecon Python dependencies
info "Installing M4rkRecon Python requirements..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
pip3 install -q -r "$SCRIPT_DIR/requirements.txt" >> "$INSTALL_LOG" 2>&1
success "Python requirements installed"

# wafw00f
install_tool "wafw00f" "pip3 install -q wafw00f"

# uro (URL deduplication)
install_tool "uro" "pip3 install -q uro"

# sqlmap
if [ ! -d "$TOOLS_DIR/sqlmap" ]; then
    info "Installing sqlmap..."
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/sqlmap" >> "$INSTALL_LOG" 2>&1
    ln -sf "$TOOLS_DIR/sqlmap/sqlmap.py" /usr/local/bin/sqlmap 2>/dev/null || true
    success "sqlmap installed"
else
    success "sqlmap already installed"
fi

# ghauri
install_tool "ghauri" "pip3 install -q ghauri"

# arjun
install_tool "arjun" "pip3 install -q arjun"

# dirsearch
if [ ! -d "$TOOLS_DIR/dirsearch" ]; then
    info "Installing dirsearch..."
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$TOOLS_DIR/dirsearch" >> "$INSTALL_LOG" 2>&1
    ln -sf "$TOOLS_DIR/dirsearch/dirsearch.py" /usr/local/bin/dirsearch 2>/dev/null || true
    pip3 install -q -r "$TOOLS_DIR/dirsearch/requirements.txt" >> "$INSTALL_LOG" 2>&1 || true
    success "dirsearch installed"
else
    success "dirsearch already installed"
fi

# theHarvester
install_tool "theHarvester" "pip3 install -q theHarvester"

# Corsy (CORS scanner)
if [ ! -d "$TOOLS_DIR/Corsy" ]; then
    info "Installing Corsy..."
    git clone --depth 1 https://github.com/s0md3v/Corsy.git "$TOOLS_DIR/Corsy" >> "$INSTALL_LOG" 2>&1
    pip3 install -q -r "$TOOLS_DIR/Corsy/requirements.txt" >> "$INSTALL_LOG" 2>&1 || true
    success "Corsy installed"
else
    success "Corsy already installed"
fi

# SecretFinder
if [ ! -d "$TOOLS_DIR/SecretFinder" ]; then
    info "Installing SecretFinder..."
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git "$TOOLS_DIR/SecretFinder" >> "$INSTALL_LOG" 2>&1
    pip3 install -q -r "$TOOLS_DIR/SecretFinder/requirements.txt" >> "$INSTALL_LOG" 2>&1 || true
    success "SecretFinder installed"
else
    success "SecretFinder already installed"
fi

# LinkFinder
if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
    info "Installing LinkFinder..."
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git "$TOOLS_DIR/LinkFinder" >> "$INSTALL_LOG" 2>&1
    pip3 install -q -r "$TOOLS_DIR/LinkFinder/requirements.txt" >> "$INSTALL_LOG" 2>&1 || true
    success "LinkFinder installed"
else
    success "LinkFinder already installed"
fi

# ParamSpider
install_tool "paramspider" "pip3 install -q paramspider"

# OpenRedireX
if [ ! -d "$TOOLS_DIR/OpenRedireX" ]; then
    info "Installing OpenRedireX..."
    git clone --depth 1 https://github.com/devanshbatham/OpenRedireX.git "$TOOLS_DIR/OpenRedireX" >> "$INSTALL_LOG" 2>&1
    success "OpenRedireX installed"
else
    success "OpenRedireX already installed"
fi

# SSRFmap
if [ ! -d "$TOOLS_DIR/SSRFmap" ]; then
    info "Installing SSRFmap..."
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git "$TOOLS_DIR/SSRFmap" >> "$INSTALL_LOG" 2>&1
    pip3 install -q -r "$TOOLS_DIR/SSRFmap/requirements.txt" >> "$INSTALL_LOG" 2>&1 || true
    success "SSRFmap installed"
else
    success "SSRFmap already installed"
fi

# ──────────────────────────────────────────────────────────────
# Step 5: Wordlists
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 5/6] Wordlists${NC}"

# Subdomain wordlist
if [ ! -f "$WORDLIST_DIR/subdomains.txt" ]; then
    info "Downloading subdomain wordlist..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
        -O "$WORDLIST_DIR/subdomains.txt" 2>/dev/null || \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -O "$WORDLIST_DIR/subdomains.txt" 2>/dev/null || true
    success "Subdomain wordlist downloaded"
else
    success "Subdomain wordlist exists"
fi

# Directory wordlist
if [ ! -f "$WORDLIST_DIR/directories.txt" ]; then
    info "Downloading directory wordlist..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -O "$WORDLIST_DIR/directories.txt" 2>/dev/null || true
    success "Directory wordlist downloaded"
else
    success "Directory wordlist exists"
fi

# Parameter wordlist
if [ ! -f "$WORDLIST_DIR/parameters.txt" ]; then
    info "Downloading parameter wordlist..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
        -O "$WORDLIST_DIR/parameters.txt" 2>/dev/null || true
    success "Parameter wordlist downloaded"
else
    success "Parameter wordlist exists"
fi

# DNS resolvers
if [ ! -f "$WORDLIST_DIR/resolvers.txt" ]; then
    info "Downloading DNS resolvers list..."
    wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
        -O "$WORDLIST_DIR/resolvers.txt" 2>/dev/null || \
    echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9" > "$WORDLIST_DIR/resolvers.txt"
    success "DNS resolvers downloaded"
else
    success "DNS resolvers exist"
fi

# ──────────────────────────────────────────────────────────────
# Step 6: Verification
# ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Step 6/6] Verification${NC}"

TOOLS_LIST=(
    subfinder httpx nuclei naabu katana dnsx shuffledns tlsx
    amass assetfinder waybackurls gau ffuf gobuster dalfox
    subjack subzy nmap masscan sslscan whois wafw00f arjun
    sqlmap ghauri
)

INSTALLED=0
MISSING=0

for tool in "${TOOLS_LIST[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ((INSTALLED++))
    else
        fail "$tool not found in PATH"
        ((MISSING++))
    fi
done

echo ""
echo -e "${CYAN}  ┌──────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │         Installation Complete!            │${NC}"
echo -e "${CYAN}  ├──────────────────────────────────────────┤${NC}"
echo -e "${CYAN}  │${NC}  Tools installed: ${GREEN}${INSTALLED}${NC}                      ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  Tools missing:   ${RED}${MISSING}${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  Log file: ${INSTALL_LOG}    ${CYAN}│${NC}"
echo -e "${CYAN}  └──────────────────────────────────────────┘${NC}"
echo ""
echo -e "  ${GREEN}Ready to run:${NC} python3 m4rkrecon.py -d <target>"
echo ""
