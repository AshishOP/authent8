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
        self.config_path = Path(__file__).parent.parent / "config" / ".semgrep.yml"
    
    # Sane defaults for Semgrep
    EXCLUDE_PATTERNS = [
        "node_modules", ".git", "dist", "build", "vendor", "__pycache__",
        ".venv", "venv", ".cache", ".tmp", "*.min.js", "*.min.css",
        "package-lock.json", "yarn.lock", "poetry.lock"
    ]
    
    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        """Run Semgrep scan and return normalized findings"""
        try:
            # Build exclude arguments
            exclude_args = []
            combined_excludes = list(set(self.EXCLUDE_PATTERNS + (ignored_patterns or [])))
            for pattern in combined_excludes:
                exclude_args.extend(["--exclude", pattern])
            
            # Use multiple rule packs for maximum coverage
            # NOTE: Custom rules removed - they can cause silent failures
            cmd = [
                "semgrep",
                "--config", "p/security-audit",
                "--config", "p/owasp-top-ten",
                "--config", "p/cwe-top-25",           # CWE Top 25 2024
                "--config", "p/secrets",              # Secrets detection
                "--config", "p/python",               # Python-specific patterns
                "--config", "p/flask",                # Flask security
                "--config", "p/django",               # Django security
                "--config", "p/jwt",                  # JWT vulnerabilities
                "--config", "p/sql-injection",        # SQL injection
                "--config", "p/command-injection",    # Command injection
                "--config", "p/xss",                  # XSS patterns
                "--config", "p/insecure-transport",   # HTTP/TLS issues
                "--config", "p/docker",               # Dockerfile security
                "--config", "p/kubernetes",           # Kubernetes manifests
                "--config", "p/terraform",            # Terraform security
                "--config", "p/aws-security",         # AWS best practices
                "--config", "p/react",                # React security patterns
                "--config", "p/typescript",           # TypeScript specific
                "--json",
                "--quiet",
                "--no-git-ignore",    # Don't skip untracked files
                "--metrics", "off",   # Privacy: no telemetry
            ] + exclude_args + [
                str(self.project_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            # Semgrep returns exit code 1 when findings exist
            if result.returncode in [0, 1] and result.stdout:
                data = json.loads(result.stdout)
                return self._parse_results(data)
            
            return []
            
        except subprocess.TimeoutExpired:
            print("⚠️  Semgrep scan timed out")
            return []
        except json.JSONDecodeError:
            print("⚠️  Semgrep returned invalid JSON")
            return []
        except Exception as e:
            print(f"⚠️  Semgrep scan failed: {e}")
            return []
    
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
