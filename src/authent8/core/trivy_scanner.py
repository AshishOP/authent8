"""
Trivy Scanner Wrapper for Authent8
Scans for dependency vulnerabilities
"""
import subprocess
import json
import importlib.resources
import platform
import os
import shutil
from pathlib import Path
from typing import List, Dict


def get_tool_path(tool_name: str) -> str:
    """Get the full path to a tool, checking local bin on Windows"""
    # Check system PATH first
    path = shutil.which(tool_name)
    if path:
        return path
    
    # Check local authent8 bin (Windows)
    if platform.system().lower() == "windows":
        local_bin = os.path.join(os.environ.get("LOCALAPPDATA", ""), "authent8", "bin")
        local_path = os.path.join(local_bin, f"{tool_name}.exe")
        if os.path.exists(local_path):
            return local_path
    else:
        local_bin = os.path.join(os.path.expanduser("~"), ".local", "bin")
        local_path = os.path.join(local_bin, tool_name)
        if os.path.exists(local_path):
            return local_path
    
    # Fallback to just the tool name
    return tool_name


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
            # Check if trivy is installed
            trivy_path = get_tool_path("trivy")
            
            # Build command - optimized for speed
            cmd = [
                trivy_path, "fs",
                "--severity", "CRITICAL,HIGH",  # Focus on important issues
                "--format", "json",
                "--scanners", "vuln,misconfig",  # Skip secrets (gitleaks handles it)
                "--skip-db-update",  # Use cached DB - huge speed boost
                "--offline-scan",  # Don't fetch from network
                "--timeout", "60s",  # 1 minute max
                str(self.project_path)
            ]
            
            # Add config if exists
            if self.config_path.exists():
                cmd.insert(2, "--config")
                cmd.insert(3, str(self.config_path))
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )
            
            # Trivy returns 0 even with findings, parse any output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_results(data)
                except json.JSONDecodeError:
                    pass
            
            # Don't show stderr - Trivy sends INFO logs there which is normal
            # Only show errors if there's a non-zero return code AND no valid findings
            
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
