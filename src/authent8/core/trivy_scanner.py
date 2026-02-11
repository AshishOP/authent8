"""
Trivy Scanner Wrapper for Authent8
Scans for dependency vulnerabilities
"""
import subprocess
import json
from pathlib import Path
from typing import List, Dict


class TrivyScanner:
    """Wrapper for Trivy vulnerability scanner"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.config_path = Path(__file__).parent.parent / "config" / ".trivy.yaml"
    
    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        """Run Trivy scan and return normalized findings"""
        cmd = [
            "trivy", "fs",
            "--config", str(self.config_path),
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--scanners", "vuln,misconfig",  # Enable IaC scanning
            "--format", "json",
            "--quiet"
        ]

        if ignored_patterns:
            for pattern in ignored_patterns:
                cmd.extend(["--skip-dirs", pattern])
                cmd.extend(["--skip-files", pattern])

        cmd.append(str(self.project_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Trivy scan timed out after 600s") from exc

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"Trivy failed: {err[:300]}")

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Trivy returned invalid JSON output") from exc

        return self._parse_results(data)
    
    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Trivy JSON output into normalized format"""
        findings = []
        
        results = data.get("Results", [])
        
        for result in results:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])
            misconfigs = result.get("Misconfigurations", [])
            
            for vuln in vulnerabilities:
                finding = {
                    "tool": "trivy",
                    "type": "vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", "")[:200],
                    "description": vuln.get("Description", "")[:500],
                    "message": vuln.get("Title", "")[:200],
                    
                    # Location
                    "file": target if target else "dependencies",
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

            for misconfig in misconfigs:
                finding = {
                    "tool": "trivy",
                    "type": "misconfig",
                    "severity": misconfig.get("Severity", "MEDIUM"),
                    "title": misconfig.get("Title", "")[:200],
                    "description": misconfig.get("Description", "")[:500],
                    "message": misconfig.get("Message", misconfig.get("Title", ""))[:200],
                    "file": target if target else "infrastructure",
                    "line": 0,
                    "rule_id": misconfig.get("ID", ""),
                    "is_false_positive": False,
                    "ai_confidence": 0,
                    "fix_suggestion": "",
                    "ai_reasoning": "",
                    "validated": False,
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
