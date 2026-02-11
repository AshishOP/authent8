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
            "--project-root", str(self.project_path),
        ]

        has_custom_rules = self.custom_rules_path.exists()
        if has_custom_rules:
            cmd.extend(["--config", str(self.custom_rules_path)])

        cmd += exclude_args + [str(self.project_path)]

        def run_command(command: List[str]) -> subprocess.CompletedProcess:
            try:
                return subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minutes
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Semgrep scan timed out after 300s") from exc

        def parse_if_json_output(result: subprocess.CompletedProcess):
            out = (result.stdout or "").strip()
            if not out:
                return None
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                return None
            # Semgrep often returns code 2 with a parseable JSON payload containing partial findings.
            if isinstance(data, dict) and "results" in data:
                return data
            return None

        result = run_command(cmd)

        # If remote rule downloads fail, fallback to local custom rules only.
        if result.returncode not in [0, 1]:
            parsed = parse_if_json_output(result)
            if parsed is not None:
                return self._parse_results(parsed)

            err = (result.stderr or result.stdout or "unknown error").strip()
            lower_err = err.lower()
            remote_fetch_failed = (
                "failed to download configuration" in lower_err
                or "could not download" in lower_err
                or "network" in lower_err
            )
            if remote_fetch_failed and has_custom_rules:
                local_only_cmd = [
                    "semgrep",
                    "--config", str(self.custom_rules_path),
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    "--metrics", "off",
                    "--project-root", str(self.project_path),
                ] + exclude_args + [str(self.project_path)]
                result = run_command(local_only_cmd)
                if result.returncode not in [0, 1]:
                    parsed_local = parse_if_json_output(result)
                    if parsed_local is not None:
                        return self._parse_results(parsed_local)
                    local_err = (result.stderr or result.stdout or "unknown error").strip()
                    raise RuntimeError(f"Semgrep failed (local fallback): {local_err[:300]}")
            else:
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
