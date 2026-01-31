"""
Gitleaks Scanner Wrapper for Authent8
Scans for hardcoded secrets
"""
import subprocess
import json
from pathlib import Path
from typing import List, Dict


class GitleaksScanner:
    """Wrapper for Gitleaks secret scanner"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.config_path = Path(__file__).parent.parent / "config" / "gitleaks.toml"
    
    def scan(self) -> List[Dict]:
        """Run Gitleaks scan and return normalized findings"""
        try:
            cmd = [
                "gitleaks", "detect",
                "--source", str(self.project_path),
                "--report-format", "json",
                "--no-git",  # Don't scan git history
                "--redact"   # Redact secret values
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            # Gitleaks returns exit code 1 when secrets are found
            # Gitleaks writes JSON to a report file, not stdout
            # Let's save to temp file instead
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                report_path = f.name
            
            cmd = [
                "gitleaks", "detect",
                "--source", str(self.project_path),
                "--report-path", report_path,
                "--report-format", "json",
                "--no-git",
                "--redact"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Read the report file
            try:
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        return self._parse_results(data)
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            finally:
                # Clean up temp file
                import os
                try:
                    os.unlink(report_path)
                except:
                    pass
            
            return []
            
        except subprocess.TimeoutExpired:
            print("⚠️  Gitleaks scan timed out")
            return []
        except Exception as e:
            print(f"⚠️  Gitleaks scan failed: {e}")
            return []
    
    def _parse_results(self, data: List[Dict]) -> List[Dict]:
        """Parse Gitleaks JSON output into normalized format"""
        findings = []
        
        for secret in data:
            rule_id = secret.get("RuleID", "unknown")
            description = secret.get("Description", f"Secret detected: {rule_id}")
            
            finding = {
                "tool": "gitleaks",
                "type": "secret",
                "severity": "CRITICAL",  # All secrets are critical
                "rule_id": rule_id,
                "secret_type": rule_id,
                "title": description,
                "description": description[:500],
                "message": f"Hardcoded secret found: {rule_id}",
                
                # Location
                "file": Path(secret.get("File", "")).name,
                "line": secret.get("StartLine", 0),
                "code_snippet": "",  # Redacted by gitleaks
                
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
    
    print(f"🔍 Running Gitleaks on: {path}\n")
    
    scanner = GitleaksScanner(path)
    results = scanner.scan()
    
    print(f"✅ Found {len(results)} secrets")
    
    if results:
        print("\nSecrets found:")
        for finding in results:
            print(f"  - {finding['secret_type']}: {finding['file']}:{finding['line']}")
