"""
Gitleaks Scanner Wrapper for Authent8
Scans for hardcoded secrets
"""
import subprocess
import json
from pathlib import Path
from typing import List, Dict

from .ignore_utils import should_ignore_path

class GitleaksScanner:
    """Wrapper for Gitleaks secret scanner"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.config_path = Path(__file__).parent.parent / "config" / "gitleaks.toml"
    
    def _create_gitleaks_config(self, tmpdir: str, ignored_patterns: List[str] = None) -> str:
        """Create a temporary gitleaks config with exclusions"""
        import os
        
        # Format ignored patterns for TOML list
        allowlist_items = [".env.example"]
        if ignored_patterns:
            allowlist_items.extend(ignored_patterns)
            
        # Deduplicate and format for TOML
        # Clean up patterns: remove leading/trailing slashes and escape dots
        clean_items = []
        for item in set(allowlist_items):
            clean = item.replace(".", "\\.").replace("*", ".*")
            clean_items.append(f"'''{clean}'''")
            
        toml_list = ",\n    ".join(clean_items)
        
        config_content = f"""
[extend]
useDefault = true

[allowlist]
paths = [
    {toml_list}
]
"""
        config_path = os.path.join(tmpdir, "gitleaks.toml")
        with open(config_path, 'w') as f:
            f.write(config_content)
        return config_path
    
    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        """Run Gitleaks scan and return normalized findings"""
        try:
            import tempfile
            import os
            
            # Create temp dir for config and report
            with tempfile.TemporaryDirectory() as tmpdir:
                report_path = os.path.join(tmpdir, "gitleaks_report.json")
                config_path = self._create_gitleaks_config(tmpdir, ignored_patterns)
                
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

                if result.returncode not in [0, 1]:
                    err = (result.stderr or result.stdout or "unknown error").strip()
                    raise RuntimeError(f"Gitleaks failed: {err[:300]}")
                
                # Read the report file
                try:
                    with open(report_path, 'r', encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list) and len(data) > 0:
                            # Filter out files using the same ignore matcher as the rest of the pipeline.
                            combined_excludes = list(dict.fromkeys(ignored_patterns or []))
                            filtered_data = [
                                s for s in data 
                                if not should_ignore_path(
                                    self.project_path / s.get("File", ""),
                                    self.project_path,
                                    combined_excludes,
                                )
                            ]
                            return self._parse_results(filtered_data)
                except (FileNotFoundError, json.JSONDecodeError):
                    if result.returncode == 1:
                        raise RuntimeError("Gitleaks reported findings but report JSON was missing/invalid")
            
            return []
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Gitleaks scan timed out after 300s")
    
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
                "file": secret.get("File", ""),
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
