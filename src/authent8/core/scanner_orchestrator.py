"""
Scanner Orchestrator for Authent8
Runs all 3 security scanners in parallel and collects results
"""
import subprocess
import json
from pathlib import Path
from typing import Dict, List
import concurrent.futures
import time

from .trivy_scanner import TrivyScanner
from .semgrep_scanner import SemgrepScanner
from .gitleaks_scanner import GitleaksScanner


class ScanOrchestrator:
    """Orchestrates Trivy, Semgrep, and Gitleaks scans"""
    
    def __init__(self, project_path: str):
        from authent8.install_tools import is_installed
        # Patch PATH sessions for local binaries
        for tool in ["trivy", "semgrep", "gitleaks"]:
            is_installed(tool)
            
        self.project_path = Path(project_path).resolve()
        self.results = {
            "trivy": [],
            "semgrep": [],
            "gitleaks": []
        }
        self.scan_duration = 0
        
        # Verify project path exists
        if not self.project_path.exists():
            raise ValueError(f"Project path does not exist: {project_path}")
            
        self.ignored_patterns = self._load_ignore_patterns()

    def _load_ignore_patterns(self) -> List[str]:
        """Load patterns from .a8ignore file or use sensible defaults"""
        # Sane defaults for almost all modern projects
        patterns = [
            "node_modules", ".git", "dist", "build", "vendor", "__pycache__", 
            ".venv", "venv", ".next", ".cache", ".tmp", 
            "0.pack", ".previewinfo", ".rscinfo", "prerender-manifest.json",
            "server-reference-manifest.json", ".vercel", "site-packages",
            "*.min.js", "*.min.css", "*.map", "*.log", "package-lock.json"
        ]
        
        ignore_file = self.project_path / ".a8ignore"
        if ignore_file.exists():
            try:
                with open(ignore_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Handle both folder/ and file.ext patterns
                            patterns.append(line.rstrip("/"))
            except Exception:
                pass
        
        # Deduplicate and return
        return list(set(patterns))
    
    def run_trivy(self) -> List[Dict]:
        """Run Trivy vulnerability scanner"""
        scanner = TrivyScanner(self.project_path)
        return scanner.scan(ignored_patterns=self.ignored_patterns)
    
    def run_semgrep(self) -> List[Dict]:
        """Run Semgrep SAST scanner"""
        scanner = SemgrepScanner(self.project_path)
        return scanner.scan(ignored_patterns=self.ignored_patterns)
    
    def run_gitleaks(self) -> List[Dict]:
        """Run Gitleaks secret scanner"""
        scanner = GitleaksScanner(self.project_path)
        return scanner.scan(ignored_patterns=self.ignored_patterns)
    
    def scan_all_parallel(self) -> Dict:
        """Run all scanners in parallel for speed"""
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_trivy = executor.submit(self.run_trivy)
            future_semgrep = executor.submit(self.run_semgrep)
            future_gitleaks = executor.submit(self.run_gitleaks)
            
            # Collect results
            self.results["trivy"] = future_trivy.result()
            self.results["semgrep"] = future_semgrep.result()
            self.results["gitleaks"] = future_gitleaks.result()
        
        self.scan_duration = time.time() - start_time
        return self.results
    
    def get_all_findings(self) -> List[Dict]:
        """Get flattened list of all findings"""
        all_findings = []
        for tool, findings in self.results.items():
            all_findings.extend(findings)
        return all_findings
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        all_findings = self.get_all_findings()
        
        return {
            "total_findings": len(all_findings),
            "by_tool": {
                "trivy": len(self.results["trivy"]),
                "semgrep": len(self.results["semgrep"]),
                "gitleaks": len(self.results["gitleaks"])
            },
            "by_severity": {
                "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in all_findings if f.get("severity") == "LOW")
            },
            "scan_duration_seconds": round(self.scan_duration, 2)
        }


if __name__ == "__main__":
    # Test the orchestrator
    import sys
    
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = "../demo/vulnerable-app"
    
    print(f"🔍 Scanning: {path}\n")
    
    orchestrator = ScanOrchestrator(path)
    results = orchestrator.scan_all_parallel()
    
    summary = orchestrator.get_summary()
    
    print(f"✅ Scan complete!")
    print(f"   Total findings: {summary['total_findings']}")
    print(f"   - Trivy: {summary['by_tool']['trivy']}")
    print(f"   - Semgrep: {summary['by_tool']['semgrep']}")
    print(f"   - Gitleaks: {summary['by_tool']['gitleaks']}")
    print(f"   Duration: {summary['scan_duration_seconds']}s")
    print(f"\n   Severity breakdown:")
    print(f"   🔴 Critical: {summary['by_severity']['critical']}")
    print(f"   🟠 High: {summary['by_severity']['high']}")
    print(f"   🟡 Medium: {summary['by_severity']['medium']}")
    print(f"   🟢 Low: {summary['by_severity']['low']}")
