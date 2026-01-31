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
    
    # Directories to exclude
    EXCLUDE_PATHS = [
        "node_modules",
        ".git",
        "dist",
        "build",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "coverage",
        ".nyc_output",
    ]
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.config_path = Path(__file__).parent.parent / "config" / "gitleaks.toml"
    
    def _create_gitleaks_config(self, tmpdir: str) -> str:
        """Create a temporary gitleaks config with exclusions"""
        import os
        config_content = """
[extend]
useDefault = true

[allowlist]
paths = [
    '''node_modules''',
    '''\.git''',
    '''dist''',
    '''build''',
    '''vendor''',
    '''__pycache__''',
    '''\.venv''',
    '''venv''',
    '''\.env\.example''',
    '''package-lock\.json''',
    '''yarn\.lock''',
]
"""
        config_path = os.path.join(tmpdir, "gitleaks.toml")
        with open(config_path, 'w') as f:
            f.write(config_content)
        return config_path
    
    def scan(self) -> List[Dict]:
        """Run Gitleaks scan and return normalized findings"""
        try:
            import tempfile
            import os
            
            # Create temp dir for config and report
            with tempfile.TemporaryDirectory() as tmpdir:
                report_path = os.path.join(tmpdir, "gitleaks_report.json")
                config_path = self._create_gitleaks_config(tmpdir)
                
                cmd = [
                    "gitleaks", "detect",
                    "--source", str(self.project_path),
                    "--report-path", report_path,
                    "--report-format", "json",
                    "--config", config_path,
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
                            # Filter out files in excluded paths
                            filtered_data = [
                                s for s in data 
                                if not any(excl in s.get("File", "") for excl in self.EXCLUDE_PATHS)
                            ]
                            return self._parse_results(filtered_data)
                except (FileNotFoundError, json.JSONDecodeError):
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
