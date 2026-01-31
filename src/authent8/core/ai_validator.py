import os
import json
from typing import List, Dict
from openai import OpenAI

class AIValidator:
    def __init__(self, api_key: str = None, base_url: str = None):
        # Priority: OPENAI_API_KEY (FastRouter compatible) > GITHUB_TOKEN
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
        
        # Check for custom base URL (for FastRouter, OpenRouter, etc.)
        if not base_url:
            base_url = os.getenv("OPENAI_BASE_URL")
        
        # Fallback: if using GITHUB_TOKEN without OPENAI_API_KEY, use GitHub Models
        if not base_url and os.getenv("GITHUB_TOKEN") and not os.getenv("OPENAI_API_KEY"):
            base_url = "https://models.inference.ai.azure.com"
        
        self.base_url = base_url
        
        # Model override from env
        self.model = os.getenv("AI_MODEL", "gpt-4o")

        if self.api_key:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url
            )
        else:
            self.client = None

    def validate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Validate findings with AI - removes false positives and adds context-aware suggestions
        """
        if not findings:
            return []
        
        if not self.client:
            print("⚠️  GITHUB_TOKEN (or OPENAI_API_KEY) not set. Skipping AI validation.")
            return findings

        # Process in batches of 3 to avoid token limits
        validated = []
        batch_size = 3
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            validated.extend(self._validate_batch(batch))
        
        return validated
    
    def _validate_batch(self, findings: List[Dict]) -> List[Dict]:
        """Validate a batch of findings with context-aware suggestions"""
        
        prompt = self._build_prompt(findings)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model, 
                messages=[
                    {
                        "role": "system", 
                        "content": """You are an expert security engineer validating security scan findings.

For EACH finding, analyze and provide:

1. **is_false_positive** (boolean): Is this a false alarm? Consider:
   - Test/example/mock data (likely false positive)
   - Commented code (likely false positive)
   - Development-only configs (may be acceptable)
   - Real production secrets/vulnerabilities (NOT false positive)

2. **confidence** (0-100): Your confidence in this assessment

3. **fix_suggestion** (string): ACTIONABLE, SPECIFIC fix. Examples:
   - For .env secrets: "Add .env to .gitignore and use environment variables in production"
   - For SQL injection: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
   - For hardcoded API key: "Move to environment variable: api_key = os.getenv('API_KEY')"
   - For eval(): "Replace eval() with ast.literal_eval() or JSON parsing"
   - For secrets in code: "Remove hardcoded secret, use secret manager or .env file"

4. **reasoning** (string): Brief explanation (max 100 chars)

5. **risk_context** (string): Explain real-world impact if exploited

IMPORTANT: Provide SPECIFIC, ACTIONABLE fixes - not generic "fix the issue" responses.

Respond ONLY with valid JSON array. No markdown, no explanation."""
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=4096
            )
            
            response_text = response.choices[0].message.content
            
            # Handle markdown code blocks
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]
            
            validations = json.loads(response_text.strip())
            
            # Merge validations with findings
            for i, finding in enumerate(findings):
                if i < len(validations):
                    validation = validations[i]
                    finding.update({
                        "is_false_positive": validation.get("is_false_positive", False),
                        "ai_confidence": validation.get("confidence", 0),
                        "fix_suggestion": validation.get("fix_suggestion", ""),
                        "ai_reasoning": validation.get("reasoning", ""),
                        "risk_context": validation.get("risk_context", ""),
                        "validated": True
                    })
                else:
                    finding.update({"validated": False})
            
            return findings
            
        except Exception as e:
            print(f"⚠️  AI validation failed for batch: {e}")
            # Fallback: mark all as unvalidated, add generic suggestions
            for finding in findings:
                finding.update({
                    "validated": False,
                    "is_false_positive": False,
                    "ai_confidence": 0,
                    "fix_suggestion": self._get_fallback_suggestion(finding),
                    "ai_reasoning": "Fallback suggestion (AI unavailable)",
                    "risk_context": self._get_risk_context(finding),
                })
            return findings
    
    def _get_risk_context(self, finding: Dict) -> str:
        """Get risk context for a finding"""
        message = finding.get("message", "").lower()
        severity = finding.get("severity", "MEDIUM")
        
        if "sql" in message:
            return "Attacker could read/modify/delete database data"
        elif "command" in message or "os.system" in message:
            return "Attacker could execute arbitrary system commands"
        elif "eval" in message:
            return "Attacker could execute arbitrary Python code"
        elif "secret" in message or "api key" in message or "hardcoded" in message:
            return "Exposed credentials could be used to access external services"
        elif "xss" in message:
            return "Attacker could steal user sessions or deface website"
        elif "pickle" in message or "deserializ" in message:
            return "Attacker could execute arbitrary code via malicious data"
        elif severity == "CRITICAL":
            return "This is a critical vulnerability that should be fixed immediately"
        elif severity == "HIGH":
            return "This vulnerability could be exploited to compromise the application"
        else:
            return "This issue should be reviewed and addressed"
    
    def _get_fallback_suggestion(self, finding: Dict) -> str:
        """Provide fallback suggestions when AI is unavailable"""
        file_path = finding.get("file", "").lower()
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()
        tool = finding.get("tool", "").lower()
        
        # .env file secrets
        if ".env" in file_path:
            return "Add .env to .gitignore and never commit secrets. Use environment variables in production."
        
        # Hardcoded secrets/API keys
        if any(x in message for x in ["hardcoded", "api key", "secret", "password", "token"]):
            return "Move secrets to environment variables or use a secret manager (AWS Secrets Manager, HashiCorp Vault)."
        
        # SQL injection
        if "sql" in message or "sql-injection" in rule_id:
            return "Use parameterized queries instead of string concatenation for SQL."
        
        # Command injection / shell
        if any(x in message for x in ["command", "shell", "os.system", "subprocess"]):
            return "Avoid shell=True, sanitize inputs, use subprocess with list arguments."
        
        # Eval
        if "eval" in message:
            return "Replace eval() with ast.literal_eval() or use JSON parsing."
        
        # XSS
        if "xss" in message or "innerhtml" in message:
            return "Sanitize user input before rendering. Use textContent instead of innerHTML."
        
        # Deserialization
        if "pickle" in message or "deserializ" in message:
            return "Use JSON instead of pickle. Never deserialize untrusted data."
        
        # Gitleaks findings
        if tool == "gitleaks":
            return "Remove or rotate this secret immediately. Add pattern to .gitignore."
        
        # Default
        return "Review this finding and apply security best practices."
    
    def _build_prompt(self, findings: List[Dict]) -> str:
        """Build AI prompt with context for better suggestions"""
        
        sanitized = []
        for idx, f in enumerate(findings):
            file_path = f.get("file", "")
            file_name = file_path.split("/")[-1] if file_path else "unknown"
            
            # Determine file context
            file_context = self._get_file_context(file_path)
            
            sanitized.append({
                "id": idx,
                "tool": f.get("tool"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "rule_id": f.get("rule_id", "")[:60],
                "message": f.get("message", f.get("description", ""))[:200],
                "code_snippet": f.get("code_snippet", "")[:150] if f.get("code_snippet") else None,
                "file": file_name,
                "file_context": file_context,
                "line": f.get("line", 0)
            })
        
        prompt = f"""Analyze these {len(sanitized)} security findings and provide validation with ACTIONABLE fix suggestions.

Findings:
{json.dumps(sanitized, indent=2)}

For EACH finding (all {len(sanitized)}), respond with:
{{
  "id": <finding_id>,
  "is_false_positive": <true/false>,
  "confidence": <0-100>,
  "fix_suggestion": "<SPECIFIC, ACTIONABLE fix - not generic>",
  "reasoning": "<brief explanation max 100 chars>",
  "risk_context": "<what could happen if exploited>"
}}

IMPORTANT: 
- For .env files: suggest adding to .gitignore, not "remove secret"
- For hardcoded secrets: suggest moving to env vars or secret manager
- For code vulnerabilities: provide actual code fix example
- Be specific about the file context (is it test file? config file? production code?)

Respond with JSON array of exactly {len(sanitized)} validation objects."""
        
        return prompt
    
    def _get_file_context(self, file_path: str) -> str:
        """Determine the context of a file for better AI suggestions"""
        path_lower = file_path.lower()
        
        if any(x in path_lower for x in ["test", "spec", "mock", "__test__", "_test."]):
            return "test_file"
        elif ".env" in path_lower:
            return "env_config"
        elif any(x in path_lower for x in ["example", "sample", "demo", "fixture"]):
            return "example_file"
        elif any(x in path_lower for x in ["config", "settings", "conf"]):
            return "config_file"
        elif any(x in path_lower for x in [".md", "readme", "docs", "documentation"]):
            return "documentation"
        elif any(x in path_lower for x in ["migration", "schema"]):
            return "database_schema"
        else:
            return "production_code"
