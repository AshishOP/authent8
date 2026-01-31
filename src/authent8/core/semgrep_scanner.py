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
    
    def scan(self) -> List[Dict]:
        """Run Semgrep scan and return normalized findings"""
        try:
            # Use direct config instead of config file for now
            cmd = [
                "semgrep",
                "--config", "p/security-audit",
                "--config", "p/owasp-top-ten",
                "--json",
                "--quiet",
                "--metrics", "off",  # Privacy: no telemetry
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
    
    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Semgrep JSON output into normalized format"""
        findings = []
        
        results = data.get("results", [])
        
        for result in results:
            # Get code snippet (limited to 300 chars for privacy)
            extra = result.get("extra", {})
            lines = extra.get("lines", "")
            code_snippet = lines[:300] if lines else ""
            
            # Map Semgrep severity to our standard
            semgrep_severity = extra.get("severity", "WARNING").upper()
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW"
            }
            severity = severity_map.get(semgrep_severity, "MEDIUM")
            
            finding = {
                "tool": "semgrep",
                "type": "sast",
                "severity": severity,
                "rule_id": result.get("check_id", ""),
                "title": extra.get("message", "")[:200],
                "description": extra.get("message", "")[:500],
                "message": extra.get("message", "")[:200],
                
                # Location
                "file": Path(result.get("path", "")).name,
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
