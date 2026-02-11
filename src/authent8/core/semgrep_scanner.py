"""
Semgrep Scanner Wrapper for Authent8
SAST scanner for code security patterns
"""
import subprocess
import json
from pathlib import Path
from typing import List, Dict


class SemgrepScanner:
    """Wrapper for Semgrep SAST scanner"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.custom_rules_path = Path(__file__).parent.parent / "config" / "custom_rules.yml"
    
    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        """Run Semgrep scan and return normalized findings"""
        exclude_args = []
        combined_excludes = list(dict.fromkeys(ignored_patterns or []))
        for pattern in combined_excludes:
            exclude_args.extend(["--exclude", pattern])

        cmd = [
            "semgrep",
            "--config", "p/security-audit",
            "--config", "p/owasp-top-ten",
            "--config", "p/cwe-top-25",
            "--config", "p/secrets",
            "--config", "p/python",
            "--config", "p/flask",
            "--config", "p/django",
            "--config", "p/jwt",
            "--config", "p/sql-injection",
            "--config", "p/command-injection",
            "--config", "p/xss",
            "--config", "p/insecure-transport",
            "--config", "p/docker",
            "--config", "p/kubernetes",
            "--config", "p/terraform",
            "--config", "p/aws-security",
            "--config", "p/react",
            "--config", "p/typescript",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics", "off",  # Privacy: no telemetry
        ]

        if self.custom_rules_path.exists():
            cmd.extend(["--config", str(self.custom_rules_path)])

        cmd += exclude_args + [str(self.project_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Semgrep scan timed out after 300s") from exc

        # Semgrep returns 1 when findings exist.
        if result.returncode not in [0, 1]:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"Semgrep failed: {err[:300]}")

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Semgrep returned invalid JSON output") from exc
        return self._parse_results(data)
    
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
    
    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Semgrep JSON output into normalized format"""
        findings = []
        
        results = data.get("results", [])
        
        for result in results:
            # Get code snippet (limited to 300 chars for privacy)
            extra = result.get("extra", {})
            lines = extra.get("lines", "")
            code_snippet = self._sanitize_text(lines[:300]) if lines else ""
            
            # Map Semgrep severity to our standard
            semgrep_severity = extra.get("severity", "WARNING").upper()
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW"
            }
            severity = severity_map.get(semgrep_severity, "MEDIUM")
            
            # Sanitize message text to remove Unicode
            message = self._sanitize_text(extra.get("message", ""))
            
            finding = {
                "tool": "semgrep",
                "type": "sast",
                "severity": severity,
                "rule_id": self._sanitize_text(result.get("check_id", "")),
                "title": message[:200],
                "description": message[:500],
                "message": message[:200],
                
                # Location
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "code_snippet": code_snippet,
                
                # AI validation (will be filled later)
                "is_false_positive": False,
                "ai_confidence": 0,
                "fix_suggestion": "",
                "ai_reasoning": "",
                "validated": False
            }
            
            findings.append(finding)
        
        return findings


if __name__ == "__main__":
    # Test the scanner
    import sys
    
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        path = Path("../demo/vulnerable-app")
    
    print(f"🔍 Running Semgrep on: {path}\n")
    
    scanner = SemgrepScanner(path)
    results = scanner.scan()
    
    print(f"✅ Found {len(results)} security issues")
    
    if results:
        print("\nSample findings:")
        for finding in results[:5]:
            print(f"  - {finding['severity']}: {finding['file']}:{finding['line']} - {finding['message'][:60]}")
