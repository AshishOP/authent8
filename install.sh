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
    # Add ALL possible pipx locations to PATH
    export PATH="$HOME/.local/bin:$HOME/Library/Python/3.13/bin:$HOME/Library/Python/3.12/bin:$HOME/Library/Python/3.11/bin:$PATH"
fi
echo -e "       ${GREEN}✓${NC} pipx ready"

# Install Authent8
echo -e "${BLUE}[4/5]${NC} Installing Authent8..."

# Try pipx first (with full path fallback)
PIPX_CMD="pipx"
if ! command -v pipx &> /dev/null; then
    # Find pipx in common locations
    for p in "$HOME/.local/bin/pipx" "$HOME/Library/Python/3.13/bin/pipx" "$HOME/Library/Python/3.12/bin/pipx" "$HOME/Library/Python/3.11/bin/pipx"; do
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
$PIPX_CMD install git+https://github.com/AshishOP/authent8.git 2>/dev/null || {
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
# Add user bin to PATH if on macOS
if [[ "$OS" == "macos" ]]; then
    USER_BIN="$HOME/Library/Python/3.13/bin"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        echo "export PATH=\"\$HOME/Library/Python/3.13/bin:\$PATH\"" >> ~/.zshrc
        export PATH="$USER_BIN:$PATH"
    fi
fi

echo ""
echo -e "${YELLOW}Optional: Set your AI API key for smart validation:${NC}"
echo -e "  export OPENAI_API_KEY=your-key-here"
echo ""

# Auto-run authent8 with the updated PATH
echo -e "${BLUE}Launching Authent8...${NC}"
exec "$SHELL" -c "export PATH=\"\$HOME/Library/Python/3.13/bin:\$HOME/Library/Python/3.12/bin:\$HOME/Library/Python/3.11/bin:\$HOME/.local/bin:\$PATH\"; authent8 --help"
