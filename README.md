# 🛡️ Authent8

> Privacy-first security scanning with AI-powered false positive removal

**Status:** Phase 1 - CLI Development In Progress

---

## 🚀 Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Run scan on vulnerable demo app
python3 cli/authent8_cli.py scan demo/vulnerable-app/

# Deactivate when done
deactivate
```

---

## 📁 Project Structure

```
authent8/
├── cli/                  # CLI tool (Click + Rich)
├── core/                 # Scanner wrappers + AI validator
├── demo/                 # Vulnerable app for testing
│   └── vulnerable-app/   # Flask app with 10+ vulnerabilities
├── config/               # Scanner configurations
│   ├── .trivy.yaml
│   ├── .semgrep.yml
│   └── gitleaks.toml
├── venv/                 # Python virtual environment
├── requirements.txt      # Python dependencies
└── .env.example          # Environment variables template
```

---

## 🔧 Development Setup

### Prerequisites
- Python 3.11+
- Trivy, Semgrep, Gitleaks (security scanners)
- GitHub token (for AI validation)

### Installation

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your GitHub token
```

---

## 🧪 Testing

### Test on Vulnerable App

```bash
# The vulnerable app contains 10+ intentional security issues:
# - SQL Injection
# - Command Injection
# - Hardcoded secrets
# - Weak cryptography (MD5)
# - Code injection (eval)
# - XSS vulnerabilities
# - And more...

python3 cli/authent8_cli.py scan demo/vulnerable-app/
```

---

## 📊 Current Features

### Phase 1 (In Progress)
- ✅ Project structure created
- ✅ Vulnerable demo app for testing
- ✅ Scanner configurations (Trivy, Semgrep, Gitleaks)
- ✅ Python virtual environment
- [ ] Scanner orchestrator
- [ ] AI validator (GitHub AI Agent)
- [ ] CLI tool with Rich UI
- [ ] Privacy report display

---

## 🔒 Privacy Guarantees

- ✅ All code scanned **locally**
- ✅ AI sees only **finding summaries** (not your code)
- ✅ **0 bytes** of source code uploaded
- ✅ No training on your data

---

## 📝 Development Log

**2026-01-31 12:00** - Phase 1 Started
- Created project structure
- Set up vulnerable demo app
- Configured all 3 security scanners
- Ready for scanner integration

---

## 🎯 Roadmap

### Phase 1: CLI Tool (Hours 0-6)
- **Hour 0-1:** ✅ Setup & structure
- **Hour 1-3:** Scanner integration
- **Hour 3-5:** AI validator
- **Hour 5-6:** CLI polish

### Phase 2: Web Application (Hours 6-12)
- Backend API (FastAPI)
- Frontend (Next.js)
- Database (PostgreSQL)

### Phase 3: Deployment (Hours 12-18)
- Railway + Vercel deployment
- Production testing

---

## 📄 License

MIT

---

**Built with ❤️ for developers who care about security AND privacy**
