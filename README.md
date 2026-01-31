# 🔒 Authent8

**Privacy-First Security Scanner** - AI-powered vulnerability detection that keeps your code local.

```
     █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗ █████╗ 
    ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██╔══██╗
    ███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ╚█████╔╝
    ██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗
    ██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ╚█████╔╝
    ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚════╝ 
```

## ✨ Features

- **🔐 Privacy-First**: Your code NEVER leaves your machine
- **🤖 AI-Powered**: GPT validates findings and removes false positives
- **⚡ Fast**: Parallel scanning with Trivy, Semgrep, and Gitleaks
- **🎨 Beautiful UI**: Rich terminal interface with progress tracking
- **📊 Actionable**: Get fix suggestions, not just warnings

## 🚀 Quick Install

### From PyPI (Recommended)
```bash
pip install authent8
```

### From Source
```bash
git clone https://github.com/authent8/authent8.git
cd authent8
pip install -e .
```

## 📋 Prerequisites

Install the security scanning tools:

```bash
# macOS
brew install trivy gitleaks
pip install semgrep

# Ubuntu/Debian
sudo apt install trivy
pip install semgrep
# Install gitleaks from https://github.com/gitleaks/gitleaks

# Or use the all-in-one Docker approach (coming soon)
```

## 🎯 Usage

### Interactive Mode (Recommended)
```bash
authent8
```
This launches the interactive menu where you can browse directories and configure scans.

### Direct Scan
```bash
# Scan a directory
authent8 scan ./my-project

# Fast scan without AI (for quick checks)
authent8 scan ./my-project --no-ai

# Verbose output (show all findings)
authent8 scan ./my-project -v

# Save report to file
authent8 scan ./my-project -o report.json

# Combine options
authent8 scan ./my-project -v --no-ai -o findings.json
```

### Browse Mode
```bash
authent8 browse
```
Interactive directory browser to select scan target.

## ⚙️ Configuration

### Environment Variables

Create a `.env` file or set environment variables:

```bash
# Required for AI validation
OPENAI_API_KEY=sk-your-key-here

# Optional: Custom AI endpoint (OpenRouter, FastRouter, etc.)
OPENAI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gpt-4o-mini

# Alternative: Use GitHub Models (free tier)
GITHUB_TOKEN=github_pat_xxx
```

### Supported AI Providers

| Provider | Base URL | Models |
|----------|----------|--------|
| OpenAI | `https://api.openai.com/v1` | gpt-4o, gpt-4o-mini |
| FastRouter | `https://go.fastrouter.ai/api/v1` | openai/gpt-4o-mini |
| OpenRouter | `https://openrouter.ai/api/v1` | Various |
| GitHub Models | `https://models.inference.ai.azure.com` | gpt-4o |

## 📊 What Gets Scanned

### Scanners

| Scanner | What it finds |
|---------|---------------|
| **Trivy** | Dependency vulnerabilities, CVEs |
| **Semgrep** | Code security patterns, OWASP Top 10 |
| **Gitleaks** | Secrets, API keys, passwords, tokens |

### Supported Languages

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, C/C++, Rust, Swift, Kotlin, Scala, and more.

## 🔒 Privacy

- **Your code stays local** - Only anonymized finding metadata is sent to AI
- **No telemetry** - We don't track usage or collect data
- **Offline mode** - Use `--no-ai` for fully offline scans
- **Open source** - Audit the code yourself

## 📈 Example Output

```
╭─────────────────────────── Scan Complete ────────────────────────────╮
│ Found 22 issues                                                       │
│ 1 CRITICAL • 7 HIGH • 14 MEDIUM                                       │
│                                                                       │
│ Scanners: trivy: 0 │ semgrep: 21 │ gitleaks: 1                        │
│ Time: 6.1s                                                            │
╰───────────────────────────────────────────────────────────────────────╯

╭─────┬─────────────────────────────────┬───────────┬──────┬──────────╮
│     │ Issue                           │ Location  │ Conf │ Tool     │
├─────┼─────────────────────────────────┼───────────┼──────┼──────────┤
│ 🔴  │ Hardcoded secret found          │ app.py:14 │ 95%  │ gitleaks │
│ 🟠  │ SQL injection vulnerability     │ app.py:26 │ 88%  │ semgrep  │
│ 🟠  │ Command injection in os.system  │ app.py:41 │ 92%  │ semgrep  │
╰─────┴─────────────────────────────────┴───────────┴──────┴──────────╯

💡 AI Fix Suggestions
────────────────────────────────────────────────────────────
  ● CRITICAL app.py:14
    Fix: Move API key to environment variable
    Confidence: 95%
```

## 🛠️ Development

```bash
# Clone the repo
git clone https://github.com/authent8/authent8.git
cd authent8

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run the CLI
authent8
```

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Built with:
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner
- [Semgrep](https://github.com/returntocorp/semgrep) - Static analysis
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal UI
- [Click](https://github.com/pallets/click) - CLI framework

---

<p align="center">
  <b>🔒 Your code stays local. Always.</b>
</p>
