<p align="center">
  <img src="https://img.shields.io/badge/Privacy-First-green?style=for-the-badge" alt="Privacy First">
  <img src="https://img.shields.io/badge/100%25-Offline-blue?style=for-the-badge" alt="100% Offline">
  <img src="https://img.shields.io/badge/Zero-Cloud-red?style=for-the-badge" alt="Zero Cloud">
</p>

<h1 align="center">🔐 Authent8</h1>

<p align="center">
  <strong>The security scanner that actually respects your privacy.</strong><br>
  Find vulnerabilities in your code without sending a single byte to the cloud.
</p>

---

## 🤔 What is Authent8?

Imagine you're building an app and you want to check if your code has security issues - like accidentally leaving passwords in your code, or having SQL injection bugs that hackers could exploit.

**The problem?** Most security scanners upload your code to their servers. That means:
- Your proprietary code goes to someone else's computer
- Your API keys and secrets might be exposed
- You have no idea what happens to your code after

**Authent8 is different.** It runs 100% on YOUR computer. Your code never leaves your machine. Ever.

## ✨ What Can It Find?

| Issue Type | Example | Why It's Bad |
|------------|---------|--------------|
| 🔑 **Hardcoded Secrets** | `API_KEY = "sk-12345..."` | Hackers can steal your API access |
| 💉 **SQL Injection** | `"SELECT * FROM users WHERE id=" + user_input` | Attackers can steal your database |
| 🖥️ **Command Injection** | `os.system(user_input)` | Hackers can run commands on your server |
| 📁 **Path Traversal** | `open(user_provided_path)` | Attackers can read any file |
| 🔓 **Insecure Deserialization** | `pickle.loads(user_data)` | Can lead to remote code execution |

## 🚀 Quick Start (2 minutes)

### Step 1: Install

**Linux/macOS:**
```bash
curl -fsSL https://authent8.dev/install.sh | bash
```

**Windows (PowerShell as Admin):**
```powershell
irm https://authent8.dev/install.ps1 | iex
```

### Step 2: Scan Your Code

```bash
# Scan current folder
authent8 .

# Scan a specific project
authent8 /path/to/your/project

# Scan with AI-powered explanations (optional)
export OPENAI_API_KEY=your-key
authent8 . --ai
```

That's it! No signup, no account, no cloud. Just security scanning.

## 📊 Example Output

```
󰒃 authent8 v1.0.0

target: my-project  files: 42  ai: off

scanning...
✓ scan complete 3.2s

⚠ CRITICAL
  • gitleaks: 2 secrets found

found 8 issues: 2 critical · 3 high · 3 medium

  ● gitleaks Hardcoded API key found: generic-api-key
           config.py:15
  ● semgrep SQL Injection: User input in database query
           models/user.py:23
  ● semgrep Command Injection: os.system with user input
           utils/runner.py:41
  ... +5 more

🔒 your code stayed local · 0 bytes sent to cloud
```

## 🛠️ How It Works (Simple Explanation)

```
┌─────────────────┐
│   Your Code     │
│   (on your PC)  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│           Authent8 Scanner              │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │ Trivy   │ │ Semgrep │ │ Gitleaks │  │
│  │(vulns)  │ │(code)   │ │(secrets) │  │
│  └────┬────┘ └────┬────┘ └────┬─────┘  │
│       │           │           │         │
│       └───────────┼───────────┘         │
│                   ▼                     │
│         Combined Results                │
└────────────────────┬────────────────────┘
                     │
                     ▼
           ┌─────────────────┐
           │  You See Issues │
           │  (all local!)   │
           └─────────────────┘
```

**What each scanner does:**
- **Trivy** - Finds known vulnerabilities in your dependencies (like "log4j" type issues)
- **Semgrep** - Finds bad code patterns (like SQL injection, command injection)
- **Gitleaks** - Finds secrets you accidentally committed (API keys, passwords)

## 🤖 Optional: AI-Powered Explanations

If you add an OpenAI API key, Authent8 can explain each vulnerability in plain English and suggest fixes:

```bash
export OPENAI_API_KEY=sk-your-key-here
authent8 . --ai
```

**Important:** Even with AI enabled, your SOURCE CODE never leaves your machine. We only send the vulnerability descriptions (not your code) to get explanations.

## 💡 Why Privacy Matters

Think about what's in your codebase:
- Database credentials
- API keys (AWS, Stripe, etc.)
- Business logic (your secret sauce)
- User data handling code

Would you hand all that to a stranger? That's what most cloud scanners ask you to do.

**With Authent8:**
- ✅ Your code stays on your machine
- ✅ No accounts or signups
- ✅ No telemetry or tracking
- ✅ Works completely offline
- ✅ Open source - verify it yourself

## 📋 Requirements

- Python 3.9+
- That's it!

The installer handles everything else (Trivy, Semgrep, Gitleaks).

## 🆘 Need Help?

**Scan taking too long?**
```bash
authent8 . --fast  # Skip some slower checks
```

**Want more details?**
```bash
authent8 . -v  # Verbose mode
```

**Export results?**
```bash
authent8 . --output results.json
```

## 🤝 Contributing

Found a bug? Have an idea? PRs welcome!

```bash
git clone https://github.com/AshishOP/authent8
cd authent8
pip install -e .
```

## 📜 License

MIT - Use it however you want!

---

<p align="center">
  <strong>Built for developers who care about privacy 🔒</strong><br>
  <a href="https://authent8.dev">authent8.dev</a>
</p>
