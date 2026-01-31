"""
Trivy Scanner Wrapper for Authent8
Scans for dependency vulnerabilities
"""
import subprocess
import json
import importlib.resources
from pathlib import Path
from typing import List, Dict


class TrivyScanner:
    """Wrapper for Trivy vulnerability scanner"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        # Use importlib.resources for package-relative config
        try:
            import authent8.config
            config_dir = Path(importlib.resources.files(authent8.config))
            self.config_path = config_dir / ".trivy.yaml"
        except:
            self.config_path = Path(__file__).parent.parent / "config" / ".trivy.yaml"
    
    def scan(self) -> List[Dict]:
        """Run Trivy scan and return normalized findings"""
        try:
            cmd = [
                "trivy", "fs",
                "--config", str(self.config_path),
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--format", "json",
                "--quiet",
                str(self.project_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return self._parse_results(data)
            
            # No findings or error
            return []
            
        except subprocess.TimeoutExpired:
            print("⚠️  Trivy scan timed out")
            return []
        except json.JSONDecodeError:
            print("⚠️  Trivy returned invalid JSON")
            return []
        except Exception as e:
            print(f"⚠️  Trivy scan failed: {e}")
            return []
    
    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Trivy JSON output into normalized format"""
        findings = []
        
        results = data.get("Results", [])
        
        for result in results:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])
            
            for vuln in vulnerabilities:
                finding = {
                    "tool": "trivy",
                    "type": "vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", "")[:200],
                    "description": vuln.get("Description", "")[:500],
                    "message": vuln.get("Title", "")[:200],
                    
                    # Location
                    "file": Path(target).name if target else "dependencies",
                    "line": 0,
                    
                    # Vulnerability details
                    "cve": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    
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
    
    print(f"🔍 Running Trivy on: {path}\n")
    
    scanner = TrivyScanner(path)
    results = scanner.scan()
    
    print(f"✅ Found {len(results)} vulnerabilities")
    
    if results:
        print("\nSample findings:")
        for finding in results[:3]:
            print(f"  - {finding['severity']}: {finding['package']} - {finding['title'][:50]}")
