"""
Bandit Scanner Wrapper for Authent8
Python-specific security scanner (catches insecure random, weak hash, debug mode)
"""
import subprocess
import json
from pathlib import Path
from typing import List, Dict


class BanditScanner:
    """Wrapper for Bandit Python security scanner"""
    
    # Directories to exclude
    EXCLUDE_DIRS = [
        "node_modules", ".git", "dist", "build", "vendor", "__pycache__",
        ".venv", "venv", "env", ".tox", "coverage", ".nyc_output",
        "site-packages", ".cache", "tmp", ".tmp",
    ]
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
    
    def scan(self) -> List[Dict]:
        """Run Bandit scan and return normalized findings"""
        try:
            # Build exclude string
            exclude_str = ",".join(self.EXCLUDE_DIRS)
            
            cmd = [
                "bandit",
                "-r", str(self.project_path),  # Recursive
                "-f", "json",                   # JSON output
                "-x", exclude_str,              # Exclude dirs
                "-ll",                          # Medium+ severity
                "-q",                           # Quiet mode
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Bandit returns exit code 1 when issues found
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_results(data)
                except json.JSONDecodeError:
                    pass
            
            return []
            
        except FileNotFoundError:
            # Bandit not installed - that's OK
            return []
        except subprocess.TimeoutExpired:
            print("⚠️  Bandit scan timed out")
            return []
        except Exception as e:
            print(f"⚠️  Bandit scan failed: {e}")
            return []
    
    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Bandit JSON output into normalized format"""
        findings = []
        
        results = data.get("results", [])
        
        for result in results:
            # Map Bandit severity
            bandit_severity = result.get("issue_severity", "MEDIUM").upper()
            severity_map = {
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM", 
                "LOW": "LOW"
            }
            severity = severity_map.get(bandit_severity, "MEDIUM")
            
            # Get code snippet
            code = result.get("code", "")[:300]
            
            finding = {
                "tool": "bandit",
                "type": "sast",
                "severity": severity,
                "rule_id": result.get("test_id", ""),
                "title": result.get("issue_text", "")[:200],
                "description": result.get("issue_text", "")[:500],
                "message": result.get("issue_text", "")[:200],
                
                # Location
                "file": Path(result.get("filename", "")).name,
                "line": result.get("line_number", 0),
                "code_snippet": code,
                
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
    
    print(f"🔍 Running Bandit on: {path}\n")
    
    scanner = BanditScanner(path)
    results = scanner.scan()
    
    print(f"✅ Found {len(results)} Python security issues")
    
    if results:
        print("\nFindings:")
        for finding in results[:10]:
            print(f"  - {finding['severity']}: {finding['file']}:{finding['line']} - {finding['message'][:60]}")
