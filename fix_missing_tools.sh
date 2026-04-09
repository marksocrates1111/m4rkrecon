#!/bin/bash
#
# M4rkRecon - Fix Missing Tools
# Run this on your VPS to install all missing tools.
# Usage: chmod +x fix_missing_tools.sh && sudo ./fix_missing_tools.sh
#

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

success() { echo -e "  ${GREEN}[+]${NC} $1"; }
info()    { echo -e "  ${CYAN}[*]${NC} $1"; }
fail()    { echo -e "  ${RED}[-]${NC} $1"; }

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:/root/go/bin

echo -e "${CYAN}[*] Fixing missing tools...${NC}\n"

# ── Python tools ──
info "Installing Python tools..."
pip3 install -q uro paramspider wafw00f ghauri python-whois theHarvester 2>/dev/null || true
success "Python tools installed"

# ── sqlmap ──
if ! command -v sqlmap &>/dev/null; then
    info "Installing sqlmap..."
    if [ ! -d "$HOME/tools/sqlmap" ]; then
        mkdir -p "$HOME/tools"
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$HOME/tools/sqlmap" 2>/dev/null
    fi
    ln -sf "$HOME/tools/sqlmap/sqlmap.py" /usr/local/bin/sqlmap 2>/dev/null || true
    success "sqlmap installed"
else
    success "sqlmap already installed"
fi

# ── Go tools that might be missing ──
info "Checking Go tools..."
for tool_install in \
    "qsreplace:github.com/tomnomnom/qsreplace@latest" \
    "kxss:github.com/Emoe/kxss@latest" \
    "subjack:github.com/haccer/subjack@latest" \
    "subzy:github.com/PentestPad/subzy@latest" \
    "dalfox:github.com/hahwul/dalfox/v2@latest"; do

    tool_name="${tool_install%%:*}"
    install_path="${tool_install##*:}"

    if ! command -v "$tool_name" &>/dev/null; then
        info "Installing $tool_name..."
        go install -v "$install_path" 2>/dev/null && success "$tool_name installed" || fail "$tool_name failed"
    else
        success "$tool_name OK"
    fi
done

# ── Verify ──
echo ""
info "Verification:"
for tool in uro paramspider wafw00f sqlmap ghauri theHarvester dalfox kxss subjack subzy qsreplace; do
    if command -v "$tool" &>/dev/null; then
        success "$tool found"
    else
        fail "$tool NOT found"
    fi
done

echo ""
echo -e "${GREEN}Done! Run 'git pull' then re-scan.${NC}"
