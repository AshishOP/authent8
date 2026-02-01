# 🤖 AI Impact Statement

## What the AI Does

Authent8 uses AI as an **optional enhancement layer** - not a core requirement. When developers enable AI mode, it helps explain security vulnerabilities in plain English and suggests actionable fixes. Think of it like having a senior security engineer look over your shoulder, explaining what each issue means and how to fix it.

**Model Used:** OpenAI GPT-4o-mini (via OpenRouter)

**Why this model?** We chose GPT-4o-mini because it's fast (~2-3 seconds per response), cost-effective, and excellent at code explanation tasks. It provides the right balance of intelligence and speed for developer workflows.

## Data Provenance & Licenses

- **Zero source code is sent to AI** - We only send vulnerability metadata (type, severity, line numbers) - never your actual code
- All scanning tools (Trivy, Semgrep, Gitleaks) are open-source with permissive licenses
- No training data is collected from users
- AI responses are ephemeral - nothing is stored or logged

## Hallucination & Bias Mitigations

We've built several guardrails:
1. **Structured prompts** - AI receives only specific vulnerability types, not open-ended queries
2. **Fact-grounded responses** - All explanations reference the actual CVE/CWE identifiers
3. **Human-in-the-loop** - AI suggestions are recommendations, developers make final decisions
4. **Fallback mode** - If AI is unavailable or returns garbage, we show raw scanner output

## Expected Outcomes

- **For Users:** Faster vulnerability triage (5x improvement), reduced learning curve for junior developers
- **For Business:** Lower security debt, fewer production incidents
- **For Safety:** Privacy-first architecture means sensitive code never leaves the developer's machine, reducing data breach risk
