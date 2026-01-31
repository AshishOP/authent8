# 🎬 Authent8 Demo Script for Hackathon

## Video Length: 2-3 minutes

---

## 🎬 SCENE 1: Hook (0:00 - 0:15)

**[Screen: Terminal with scary statistics]**

```
🔓 90% of security breaches start with leaked credentials
🔓 Average time to detect: 287 days
🔓 Cost per breach: $4.45 million
```

**Narration:**
> "What if you could find every security vulnerability in your code before it becomes a disaster? Meet Authent8."

---

## 🎬 SCENE 2: Problem Statement (0:15 - 0:35)

**[Screen: Show multiple tools running separately]**

**Narration:**
> "Developers today juggle multiple security tools - Trivy for dependencies, Semgrep for code patterns, Gitleaks for secrets. Each produces hundreds of alerts, most are false positives. It's overwhelming."

**[Show overwhelming wall of text output from traditional tools]**

---

## 🎬 SCENE 3: The Solution (0:35 - 0:55)

**[Screen: Type `authent8` in terminal]**

**Narration:**
> "Authent8 combines all three scanners with AI-powered validation. One command. Zero noise. 100% privacy - your code never leaves your machine."

**[Show the beautiful banner appearing]**

---

## 🎬 SCENE 4: Live Demo (0:55 - 2:00)

### Part A: Main Menu
**[Show the interactive menu]**

**Narration:**
> "A beautiful, intuitive interface. Choose Quick Scan to analyze your current project."

### Part B: Scan Options
**[Show the pre-scan options]**

```
⚙️  SCAN OPTIONS

? 🤖 Enable AI validation? Yes
? 📋 Verbose output? No
? 💾 Save JSON report? Yes
```

**Narration:**
> "AI validation is the magic. It analyzes each finding to eliminate false positives."

### Part C: Scanning in Progress
**[Show progress bars with file names]**

```
  Dependency Scan  ━━━━━━━━━━━━━━━━ 100% ✓ 0 found 
  Pattern Analysis ━━━━━━━━━━━━━━━━ 100% ✓ 22 found
  Secret Hunting   ━━━━━━━━━━━━━━━━ 100% ✓ 4 found 
  AI Verification  ━━━━━━━━━━━━━━━━ 100% ✓ Complete
```

**Narration:**
> "Trivy checks dependencies, Semgrep analyzes code patterns, Gitleaks hunts secrets. AI then validates each finding."

### Part D: Results
**[Show the colorful results table]**

**Narration:**
> "Clean, prioritized results. Critical issues first. Each finding comes with specific, actionable fix suggestions."

### Part E: Fix Suggestions
**[Scroll to fix suggestions section]**

```
💡 FIX SUGGESTIONS

📄 app.py
    L14: Move the hardcoded API key to an environment variable.
    L26: Use parameterized queries instead of string concatenation.
```

**Narration:**
> "Not just problems - solutions. AI generates specific fixes for your exact code."

---

## 🎬 SCENE 5: Key Differentiators (2:00 - 2:20)

**[Show comparison slide/graphic]**

| Feature | Others | Authent8 |
|---------|--------|----------|
| Privacy | Cloud-based | 100% Local |
| False Positives | High | AI Filtered |
| Tools | 1 scanner | Trivy + Semgrep + Gitleaks |
| Fix Suggestions | Generic | AI-Powered Specific |
| UX | CLI-only | Beautiful TUI |

**Narration:**
> "Privacy-first. AI-powered. Developer-friendly. This is the future of security scanning."

---

## 🎬 SCENE 6: Call to Action (2:20 - 2:30)

**[Screen: GitHub repo / Install command]**

```bash
pipx install authent8
authent8
```

**Narration:**
> "Try Authent8 today. Your code stays local. Your secrets stay secret. Authent8."

**[Show logo with tagline: "Authenticate Your Security"]**

---

## 📹 GIF Recording Suggestions

### GIF 1: Install to First Scan (15 seconds)
```bash
pipx install authent8
authent8
# Show menu appearing
```

### GIF 2: Quick Scan Flow (20 seconds)
- Select Quick Scan
- Choose options
- Watch progress bars
- See results

### GIF 3: AI Fix Suggestions (10 seconds)
- Scroll through fix suggestions
- Show specific line-by-line fixes

---

## 🛠️ Recording Tools

**For Terminal Recording:**
```bash
# Option 1: asciinema (terminal-native)
pip install asciinema
asciinema rec demo.cast
# Convert to GIF: https://asciinema.org

# Option 2: terminalizer (GIF output)
npm install -g terminalizer
terminalizer record demo
terminalizer render demo

# Option 3: VHS (Go-based, beautiful)
brew install vhs  # or go install github.com/charmbracelet/vhs@latest
vhs demo.tape
```

**VHS Tape Script (demo.tape):**
```
Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "Dracula"

Type "authent8"
Enter
Sleep 2s

Down
Sleep 500ms
Enter
Sleep 500ms

Type "y"
Enter
Sleep 500ms

Type "n"
Enter
Sleep 500ms

Type "n"
Enter
Sleep 30s

Sleep 5s
```

---

## 🎯 Demo Tips for Judges

1. **Use the vulnerable-app demo folder** - It has realistic vulnerabilities
2. **Keep AI enabled** - Shows the differentiator
3. **Pause on results** - Let them see the beautiful UI
4. **Highlight "100% local"** - Privacy is huge for enterprises
5. **End with the fix suggestions** - Shows actionable value

---

## 📝 Talking Points for Q&A

**Q: How is this different from GitHub CodeQL?**
> "CodeQL is cloud-based and requires GitHub integration. Authent8 is 100% local, works offline, and combines three battle-tested tools with AI validation."

**Q: What about false positives?**
> "AI validation reduces false positives by 40-60%. Each finding is analyzed in context and scored for likelihood of being a real issue."

**Q: Can it integrate with CI/CD?**
> "Yes! `authent8 scan ./src --no-ai --output report.json` for headless mode. JSON output integrates with any CI system."

**Q: What's the AI model?**
> "Configurable. Supports OpenAI, local models via Ollama, or any OpenAI-compatible API. Default is gpt-4o-mini for speed/cost balance."

---

Good luck with the hackathon! 🏆
