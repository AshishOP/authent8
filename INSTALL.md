# 🚀 Authent8 Installation Guide

This guide will help you install and run Authent8 on your machine.

## Prerequisites

Before installing Authent8, you need to install the underlying security scanners:

### 1. Install Trivy (Vulnerability Scanner)

**macOS:**
```bash
brew install trivy
```

**Ubuntu/Debian:**
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Windows (with Chocolatey):**
```bash
choco install trivy
```

### 2. Install Semgrep (Code Scanner)

```bash
pip install semgrep
# or
pip3 install semgrep
```

### 3. Install Gitleaks (Secret Scanner)

**macOS:**
```bash
brew install gitleaks
```

**Ubuntu/Linux:**
```bash
# Download latest release
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

**Windows:**
```bash
# Download from: https://github.com/gitleaks/gitleaks/releases
# Add to PATH
```

### 4. Verify installations
```bash
trivy --version
semgrep --version
gitleaks version
```

---

## Install Authent8

### Option A: From GitHub (Recommended for now)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/authent8.git
cd authent8

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install authent8
pip install -e .
```

### Option B: Direct from Git URL

```bash
pip install git+https://github.com/YOUR_USERNAME/authent8.git
```

### Option C: From PyPI (when published)

```bash
pip install authent8
```

---

## Configuration (Optional)

For AI-powered false positive detection, you need an API key:

### Create a `.env` file:

```bash
# In your home directory or the directory where you run authent8
touch ~/.authent8.env
```

Add your API key:
```bash
# OpenAI API Key
OPENAI_API_KEY=sk-your-key-here

# OR use FastRouter (cheaper)
OPENAI_API_KEY=sk-your-fastrouter-key
OPENAI_BASE_URL=https://go.fastrouter.ai/api/v1
AI_MODEL=openai/gpt-4o-mini
```

**Without API key:** Authent8 works fine without AI - just use `--no-ai` flag for faster offline scans!

---

## Usage

### Interactive Mode (Easiest)
```bash
authent8
```
This opens the interactive menu where you can browse directories and configure scans.

### Direct Scan
```bash
# Scan current directory
authent8 scan .

# Scan a specific directory
authent8 scan /path/to/your/project

# Fast scan without AI (recommended for quick checks)
authent8 scan ./my-project --no-ai

# Full scan with all findings
authent8 scan ./my-project -v

# Save report to file
authent8 scan ./my-project -o security-report.json
```

### Check Version
```bash
authent8 --version
```

### Get Help
```bash
authent8 --help
authent8 scan --help
```

---

## Troubleshooting

### "command not found: authent8"
- Make sure pip's bin directory is in your PATH
- Try: `python -m authent8.cli.main` instead
- Or run: `pip show authent8` to verify installation

### "trivy: command not found"
- Install Trivy (see prerequisites above)
- Verify: `which trivy` or `trivy --version`

### "semgrep: command not found"
- Install: `pip install semgrep`
- Verify: `semgrep --version`

### "gitleaks: command not found"
- Install Gitleaks (see prerequisites above)
- Verify: `gitleaks version`

### AI validation not working
- Check if OPENAI_API_KEY is set: `echo $OPENAI_API_KEY`
- Use `--no-ai` flag to skip AI validation

---

## Quick Test

After installation, test with a sample scan:

```bash
# Create a test file with a vulnerability
mkdir test-scan && cd test-scan
echo 'API_KEY = "sk-1234567890abcdef"' > test.py
echo 'import os; os.system(input())' >> test.py

# Run authent8
authent8 scan . --no-ai

# Clean up
cd .. && rm -rf test-scan
```

---

## Support

- Issues: https://github.com/YOUR_USERNAME/authent8/issues
- Documentation: See README.md

---

**🔒 Remember: Your code stays local! Only anonymized finding metadata is sent to AI for validation.**
