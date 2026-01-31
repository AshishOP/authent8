import os
import sys
import json
from typing import List, Dict
from openai import OpenAI

# Force UTF-8 output to avoid encoding errors
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

class AIValidator:
    def __init__(self, api_key: str = None, base_url: str = None):
        # Priority: FASTROUTER_API_KEY > OPENAI_API_KEY > GITHUB_TOKEN
        self.api_key = api_key or os.getenv("FASTROUTER_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
        
        # Skip placeholder keys
        if self.api_key and self.api_key.startswith("your-"):
            self.api_key = os.getenv("FASTROUTER_API_KEY") or os.getenv("GITHUB_TOKEN")
        
        # Check for custom base URL (for FastRouter, OpenRouter, etc.)
        if not base_url:
            base_url = os.getenv("FASTROUTER_API_HOST") or os.getenv("OPENAI_BASE_URL")
        
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
        Validate findings with AI - removes false positives
        """
        if not findings:
            return []
        
        if not self.client:
            print("⚠️  GITHUB_TOKEN (or OPENAI_API_KEY) not set. Skipping AI validation.")
            return findings

        # Process in batches of 3 to avoid token limits (413 errors)
        # Smaller batches = more reliable, especially for code snippets
        validated = []
        batch_size = 3
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            validated.extend(self._validate_batch(batch))
        
        return validated
    
    def _validate_batch(self, findings: List[Dict]) -> List[Dict]:
        """Validate a batch of findings"""
        
        prompt = self._build_prompt(findings)
        
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
   - Test/mock data
   - Example code
   - Commented code
   - Development dependencies
   - Documentation examples
   
2. confidence (0-100) - How confident are you in this assessment?
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
            for i, finding in enumerate(findings):
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
            print(f"AI validation error: {err_msg[:100]}", file=sys.stderr)
            
            # Fallback: mark all as unvalidated
            for finding in findings:
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
                "code_snippet": self._sanitize_text(str(f.get("code_snippet", "")))[:100] if f.get("code_snippet") else None,
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
