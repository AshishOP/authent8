#!/bin/bash
# Authent8 Installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/AshishOP/authent8/main/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "  █████  ██   ██ ████████ ██  ██ ███████ ███   ██ ████████  █████ "
echo " ██   ██ ██   ██    ██    ██  ██ ██      ████  ██    ██    ██   ██"
echo " ███████ ██   ██    ██    ██████ █████   ██ ██ ██    ██     █████ "
echo " ██   ██ ██   ██    ██    ██  ██ ██      ██  ████    ██    ██   ██"
echo " ██   ██  █████     ██    ██  ██ ███████ ██   ███    ██     █████ "
echo -e "${NC}"
echo -e "${GREEN}Privacy-First Security Scanner${NC}"
echo ""

# Detect OS and Architecture
OS="unknown"
ARCH="unknown"
GITLEAKS_ARCH="unknown"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

# Detect Architecture
uname_m=$(uname -m)
case $uname_m in
    x86_64)
        ARCH="x64"
        GITLEAKS_ARCH="x64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        GITLEAKS_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}❌ Unsupported architecture: $uname_m"${NC}
        exit 1
        ;;
esac

echo -e "${BLUE}[1/5]${NC} Detected: $OS ($ARCH)"

# Check Python
echo -e "${BLUE}[2/5]${NC} Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo -e "       ${GREEN}✓${NC} Python $PYTHON_VERSION found"
else
    echo -e "       ${RED}✗${NC} Python 3 not found. Installing..."
    if [[ "$OS" == "macos" ]]; then
        brew install python3
    elif [[ "$DISTRO" == "debian" ]]; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
    elif [[ "$DISTRO" == "fedora" ]]; then
        sudo dnf install -y python3 python3-pip
    elif [[ "$DISTRO" == "arch" ]]; then
        sudo pacman -S python python-pip
    fi
fi

# Check pipx
echo -e "${BLUE}[3/5]${NC} Checking pipx..."
if ! command -v pipx &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing pipx..."
    if [[ "$DISTRO" == "arch" ]]; then
        sudo pacman -S --noconfirm python-pipx
    else
        python3 -m pip install --user pipx 2>/dev/null || python3 -m pip install --user --break-system-packages pipx
    fi
    python3 -m pipx ensurepath 2>/dev/null || true
    # Add common pipx paths to current session
    export PATH="$HOME/.local/bin:$PATH"
fi
echo -e "       ${GREEN}✓${NC} pipx ready"

# Install Authent8
echo -e "${BLUE}[4/5]${NC} Installing Authent8..."

# Try pipx first (with full path fallback)
PIPX_CMD="pipx"
if ! command -v pipx &> /dev/null; then
    # Find pipx in common locations
    for p in "$HOME/.local/bin/pipx" "$HOME/Library/Python/*/bin/pipx"; do
        if [ -f "$p" ]; then
            PIPX_CMD="$p"
            break
        fi
    done
fi

# Clean up any previous failed install
rm -rf /tmp/authent8-install 2>/dev/null || true

# Use pipx for isolation (works on all distros including Arch)
echo -e "       ${YELLOW}→${NC} Installing from GitHub..."
$PIPX_CMD install git+https://github.com/AshishOP/authent8.git --force 2>/dev/null || {
    echo -e "       ${YELLOW}→${NC} Cloning and installing locally..."
    cd /tmp
    rm -rf authent8-install 2>/dev/null
    git clone https://github.com/AshishOP/authent8.git authent8-install
    cd authent8-install
    $PIPX_CMD install .
    cd /tmp
    rm -rf authent8-install
}
echo -e "       ${GREEN}✓${NC} Authent8 installed"

# Install security tools
echo -e "${BLUE}[5/5]${NC} Installing security scanners..."

# Trivy
if ! command -v trivy &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing Trivy..."
    if [[ "$OS" == "macos" ]]; then
        brew install trivy
    elif [[ "$DISTRO" == "debian" ]]; then
        sudo apt-get install wget apt-transport-https gnupg lsb-release -y
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update && sudo apt-get install trivy -y
    elif [[ "$DISTRO" == "fedora" ]]; then
        # Detect arch for rpm
        TRIVY_ARCH="64bit"
        if [[ "$ARCH" == "arm64" ]]; then TRIVY_ARCH="ARM64"; fi
        sudo rpm -ivh "https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-${TRIVY_ARCH}.rpm"
    else
        # Install to local bin to avoid sudo
        mkdir -p "$HOME/.local/bin"
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$HOME/.local/bin"
    fi
fi
echo -e "       ${GREEN}✓${NC} Trivy ready"

# Semgrep
if ! command -v semgrep &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing Semgrep..."
    $PIPX_CMD install semgrep 2>/dev/null || $PIPX_CMD install semgrep --force
fi
echo -e "       ${GREEN}✓${NC} Semgrep ready"

# Gitleaks
if ! command -v gitleaks &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing Gitleaks..."
    if [[ "$OS" == "macos" ]]; then
        brew install gitleaks
    else
        # Download latest release with correct architecture
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        if [ -z "$GITLEAKS_VERSION" ]; then GITLEAKS_VERSION="8.18.1"; fi
        
        echo -e "       ${BLUE}Downloading Gitleaks v${GITLEAKS_VERSION} for ${OS}_${GITLEAKS_ARCH}...${NC}"
        mkdir -p "$HOME/.local/bin"
        curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${GITLEAKS_ARCH}.tar.gz" | tar xz -C "$HOME/.local/bin" gitleaks
        chmod +x "$HOME/.local/bin/gitleaks"
    fi
fi
echo -e "       ${GREEN}✓${NC} Gitleaks ready"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Run ${BLUE}authent8${NC} to start scanning!"

# Dynamic PATH addition for macOS/Linux
if [[ "$OS" == "macos" ]]; then
    # Add all Python bin directories found
    for bin_dir in $HOME/Library/Python/*/bin; do
        if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
             export PATH="$bin_dir:$PATH"
        fi
    done
fi
export PATH="$HOME/.local/bin:$PATH"

echo -e "${YELLOW}💡 Pro Tip: Stop managing .env files manually!${NC}"
echo -e "   Run ${BLUE}authent8${NC} and go to ${BLUE}⚙ Configuration${NC} to set up your AI key interactively."
echo ""

# Launch
exec "$SHELL" -c "export PATH=\"$PATH\"; authent8 --help"
