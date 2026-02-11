import os
import sys
import json
from typing import List, Dict

# Force UTF-8 output to avoid encoding errors
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

class AIValidator:
    def __init__(self, api_key: str = None, base_url: str = None, model: str = None):
        # Determine API Key: use explicit arg ONLY if provided, otherwise check env
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = (
                os.getenv("AUTHENT8_AI_KEY") or 
                os.getenv("FASTROUTER_API_KEY") or 
                os.getenv("OPENAI_API_KEY") or 
                os.getenv("GITHUB_TOKEN")
            )
        
        # Skip placeholder keys if they came from env
        if self.api_key and isinstance(self.api_key, str) and self.api_key.startswith("your-"):
            self.api_key = None
        
        # Check for custom base URL
        if not base_url:
            base_url = (
                os.getenv("AUTHENT8_AI_BASE_URL") or 
                os.getenv("FASTROUTER_API_HOST") or 
                os.getenv("OPENAI_BASE_URL")
            )
        
        # Fallback: if using GITHUB_TOKEN without OPENAI_API_KEY, use GitHub Models
        if not base_url and os.getenv("GITHUB_TOKEN") and not os.getenv("OPENAI_API_KEY") and not os.getenv("AUTHENT8_AI_KEY"):
            base_url = "https://models.inference.ai.azure.com"
        
        self.base_url = base_url
        
        # Model override hierarchy
        self.model = model or os.getenv("AUTHENT8_AI_MODEL") or os.getenv("AI_MODEL", "gpt-4o-mini")

        self.client = None
        if self.api_key:
            try:
                from openai import OpenAI

                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url
                )
            except Exception:
                # Keep client unset; scanner will continue without AI validation.
                self.client = None

    def test_connection(self) -> bool:
        """Test connection to the AI provider with a dummy request"""
        if not self.client:
            return False
        try:
            # Minimal request to verify key and model existence
            self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
                timeout=12 
            )
            return True
        except Exception as e:
            err_msg = str(e).lower()
            # Categorize the error for the CLI wizard
            if "401" in err_msg or "unauthorized" in err_msg or "invalid_api_key" in err_msg:
                raise Exception(f"AUTH_ERROR: {str(e)}")
            if "model" in err_msg and ("404" in err_msg or "not found" in err_msg or "no such" in err_msg):
                raise Exception(f"MODEL_ERROR: {str(e)}")
            # Fallback
            raise e

    def validate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Validate findings using Heuristics + AI
        """
        if not findings:
            return []
            
        # 1. Apply deterministic heuristics first (Fast & Accurate)
        self._apply_heuristics(findings)
        
        # 2. Identify what still needs AI validation
        to_validate_with_ai = [f for f in findings if not f.get("validated")]
        
        if not to_validate_with_ai:
            return findings
        
        if not self.client:
            print("⚠️  GITHUB_TOKEN (or OPENAI_API_KEY) not set. Skipping AI validation.")
            return findings

        # 3. Process remaining with AI in batches
        validated = []
        batch_size = 3
        
        for i in range(0, len(to_validate_with_ai), batch_size):
            batch = to_validate_with_ai[i:i+batch_size]
            self._validate_batch(batch) # Modifies in-place
            
        return findings

    def _apply_heuristics(self, findings: List[Dict]):
        """Apply deterministic rules to catch obvious false positives"""
        for f in findings:
            path = f.get("file", "").lower()
            file_name = os.path.basename(path)
            rule = str(f.get("rule_id", "")).lower()
            code = str(f.get("code_snippet", "")).lower()
            message = str(f.get("message", "")).lower()
            tool = str(f.get("tool", "")).lower()
            is_test_or_demo = (
                "/tests/" in path
                or "\\tests\\" in path
                or "/test/" in path
                or "\\test\\" in path
                or "/mocks/" in path
                or "\\mocks\\" in path
                or "/fixtures/" in path
                or "\\fixtures\\" in path
                or file_name.startswith("test_")
                or file_name.endswith("_test.py")
                or "security_check.py" in file_name
            )
            
            # RULE 1: Known internal test fixture file.
            if "security_check.py" in file_name:
                f.update({
                    "is_false_positive": True,
                    "ai_confidence": 100,
                    "ai_reasoning": "Known internal fixture file.",
                    "validated": True
                })
                continue

            # RULE 2: Install scripts for tool bootstrap logic.
            if "install" in path or "setup.py" in path:
                if "urllib" in rule or "permissions" in rule or "chmod" in code:
                    f.update({
                        "is_false_positive": True,
                        "ai_confidence": 95,
                        "ai_reasoning": "Standard installation script behavior.",
                        "validated": True
                    })
                    continue

            # RULE 3: Documentation/example files.
            if path.endswith(".md") or path.endswith(".txt"):
                f.update({
                    "is_false_positive": True,
                    "ai_confidence": 95,
                    "ai_reasoning": "Secrets in documentation are likely examples.",
                    "validated": True
                })
                continue

            # RULE 4: False positive manager logic file itself.
            if "false_positives.py" in path:
                f.update({
                    "is_false_positive": True,
                    "ai_confidence": 100,
                    "ai_reasoning": "Logic handling false positives often mimics vulnerabilities.",
                    "validated": True
                })
                continue

            # RULE 5: Placeholder/demo secrets in test fixtures.
            if tool == "gitleaks" and is_test_or_demo:
                placeholder_markers = [
                    "example",
                    "dummy",
                    "placeholder",
                    "sample",
                    "test",
                    "mock",
                    "0000",
                    "12345",
                ]
                evidence = f"{message} {code} {rule}"
                if any(marker in evidence for marker in placeholder_markers):
                    f.update({
                        "is_false_positive": True,
                        "ai_confidence": 90,
                        "ai_reasoning": "Likely placeholder secret in test/demo fixture.",
                        "validated": True
                    })
                    continue
    
    def _validate_batch(self, findings: List[Dict]) -> List[Dict]:
        """Validate a batch of findings"""
        
        # 1. Apply heuristics first
        self._apply_heuristics(findings)
        
        # 2. Filter out what's already validated by heuristics
        to_validate = [f for f in findings if not f.get("validated")]
        
        if not to_validate:
            return findings

        # Enhance findings with actual file content if snippet is missing
        for finding in to_validate:
            if not finding.get("code_snippet"):
                try:
                    file_path = finding.get("file")
                    line_num = int(finding.get("line", 0))
                    if file_path and line_num > 0 and os.path.exists(file_path):
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            # Get context: line-5 to line+5 (11 lines total)
                            start = max(0, line_num - 6)
                            end = min(len(lines), line_num + 5)
                            snippet = "".join(lines[start:end])
                            finding["code_snippet"] = snippet.strip()
                except Exception:
                    pass  # Fail silently on file read errors

        prompt = self._build_prompt(to_validate)
        
        try:
            # Use model from env (AI_MODEL) or default to gpt-4o
            response = self.client.chat.completions.create(
                model=self.model, 
                messages=[
                    {
                        "role": "system", 
                        "content": """You are a security expert validating security scan findings.
For EACH finding, determine:
1. is_false_positive (boolean) - Is this a false alarm? Common false positives:
   - Test Files: Any file named '*test*', '*mock*', 'security_check.py', or inside 'tests/' folder is likely a False Positive.
   - Install Scripts: 'install.sh', 'install_tools.py', 'setup.py' often require permissions (chmod 755) and downloads (urllib). These are False Positives.
   - Documentation: Files like .md, .txt containing secrets are examples.
   - Examples/Placeholders: Credentials like '0000', 'EXAMPLE', '123456'.
   - Checksums: MD5 used for integrity/ETag is SAFE (False Positive).

2. confidence (0-100) - How confident are you? (Higher for test files/examples)
3. fix_suggestion (string) - One-line actionable fix if real issue
4. reasoning (string) - Brief explanation (max 100 chars)

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
            for i, finding in enumerate(to_validate):
                if i < len(validations):
                    validation = validations[i]
                    finding.update({
                        "is_false_positive": validation.get("is_false_positive", False),
                        "ai_confidence": validation.get("confidence", 0),
                        "fix_suggestion": validation.get("fix_suggestion", ""),
                        "ai_reasoning": validation.get("reasoning", ""),
                        "validated": True
                    })
                else:
                    finding.update({"validated": False})
            
            return findings
            
        except Exception as e:
            # Log error for debugging
            import sys
            err_msg = str(e).encode('ascii', 'ignore').decode('ascii')
            # Only print error if it's not a dry-run or expected failure
            # print(f"AI validation error: {err_msg[:100]}", file=sys.stderr)
            
            # Fallback: mark all as unvalidated
            for finding in to_validate:
                finding.update({
                    "validated": False,
                    "is_false_positive": False,
                    "ai_confidence": 0,
                    "ai_error": err_msg[:100]
                })
            return findings
    
    def _sanitize_text(self, text: str) -> str:
        """Remove non-ASCII characters to avoid encoding issues"""
        if not text:
            return ""
        # Replace common Unicode chars with ASCII equivalents
        replacements = {
            '\u2026': '...',  # ellipsis
            '\u2019': "'",    # right single quote
            '\u2018': "'",    # left single quote
            '\u201c': '"',    # left double quote
            '\u201d': '"',    # right double quote
            '\u2014': '--',   # em dash
            '\u2013': '-',    # en dash
            '\u00a0': ' ',    # non-breaking space
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        # Remove any remaining non-ASCII
        return text.encode('ascii', 'ignore').decode('ascii')
    
    def _build_prompt(self, findings: List[Dict]) -> str:
        """Build AI prompt with minimal context"""
        
        sanitized = []
        for idx, f in enumerate(findings):
            # More aggressive truncation to prevent 413 errors
            # Also sanitize text to avoid Unicode encoding issues
            sanitized.append({
                "id": idx,
                "tool": f.get("tool"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "rule_id": self._sanitize_text(str(f.get("rule_id", "")))[:50],
                "message": self._sanitize_text(str(f.get("message", f.get("description", ""))))[:150],
                "code_snippet": self._sanitize_text(str(f.get("code_snippet", "")))[:1200] if f.get("code_snippet") else None,
                "file_hint": str(f.get("file", ""))[:50],
                "line": f.get("line", 0)
            })
        
        prompt = f"""Analyze these {len(sanitized)} security findings and validate each one.

Findings:
{json.dumps(sanitized, indent=2, ensure_ascii=True)}

For EACH finding (all {len(sanitized)} of them), provide:
{{
  "id": <finding_id>,
  "is_false_positive": <true/false>,
  "confidence": <0-100>,
  "fix_suggestion": "<one line fix if real issue, empty if false positive>",
  "reasoning": "<brief explanation max 100 chars>"
}}

Respond with JSON array of exactly {len(sanitized)} validation objects."""
        
        return prompt
