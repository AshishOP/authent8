#!/bin/bash
# Authent8 Installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/yourusername/authent8/main/install.sh | bash

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

# Detect OS
OS="unknown"
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

echo -e "${BLUE}[1/5]${NC} Detected: $OS"

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
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
fi
echo -e "       ${GREEN}✓${NC} pipx ready"

# Install Authent8
echo -e "${BLUE}[4/5]${NC} Installing Authent8..."
pipx install authent8 2>/dev/null || pipx upgrade authent8 2>/dev/null || {
    # If not on PyPI yet, install from GitHub
    echo -e "       ${YELLOW}→${NC} Installing from GitHub..."
    pipx install git+https://github.com/yourusername/authent8.git 2>/dev/null || {
        echo -e "       ${RED}✗${NC} Could not install from PyPI or GitHub"
        echo -e "       ${YELLOW}→${NC} Trying local install..."
        cd /tmp
        git clone https://github.com/yourusername/authent8.git authent8-install
        cd authent8-install
        pipx install .
        cd ..
        rm -rf authent8-install
    }
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
        sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.rpm
    else
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    fi
fi
echo -e "       ${GREEN}✓${NC} Trivy ready"

# Semgrep
if ! command -v semgrep &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing Semgrep..."
    python3 -m pip install --user semgrep
fi
echo -e "       ${GREEN}✓${NC} Semgrep ready"

# Gitleaks
if ! command -v gitleaks &> /dev/null; then
    echo -e "       ${YELLOW}→${NC} Installing Gitleaks..."
    if [[ "$OS" == "macos" ]]; then
        brew install gitleaks
    else
        # Download latest release
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | sudo tar xz -C /usr/local/bin gitleaks
    fi
fi
echo -e "       ${GREEN}✓${NC} Gitleaks ready"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Run ${BLUE}authent8${NC} to start scanning!"
echo ""
echo -e "${YELLOW}Optional: Set your AI API key for smart validation:${NC}"
echo -e "  export OPENAI_API_KEY=your-key-here"
echo ""
