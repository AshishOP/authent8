"""
Scanner Orchestrator for Authent8
Runs all scanners in parallel and collects results
"""
from pathlib import Path
from typing import Dict, List
import concurrent.futures
import time

from .trivy_scanner import TrivyScanner
from .semgrep_scanner import SemgrepScanner
from .gitleaks_scanner import GitleaksScanner
from .bandit_scanner import BanditScanner
from .detect_secrets_scanner import DetectSecretsScanner
from .checkov_scanner import CheckovScanner
from .grype_scanner import GrypeScanner
from .osv_scanner import OSVScanner

from .false_positives import FalsePositiveManager
from .ignore_utils import load_ignore_patterns

class ScanOrchestrator:
    """Orchestrates security scanners and normalizes their outputs."""
    ONLINE_REQUIRED_TOOLS = {"trivy", "semgrep", "grype", "osv-scanner"}
    ALL_TOOLS = [
        "trivy",
        "semgrep",
        "gitleaks",
        "bandit",
        "detect-secrets",
        "checkov",
        "grype",
        "osv-scanner",
    ]
    
    def __init__(self, project_path: str):
        from authent8.install_tools import is_installed
        # Patch PATH sessions for local binaries
        for tool in self.ALL_TOOLS:
            is_installed(tool)
            
        self.project_path = Path(project_path).resolve()
        self.results = {tool: [] for tool in self.ALL_TOOLS}
        self.scan_errors: Dict[str, str] = {}
        self.scan_duration = 0
        self.fp_manager = FalsePositiveManager(self.project_path)
        
        # Verify project path exists
        if not self.project_path.exists():
            raise ValueError(f"Project path does not exist: {project_path}")
            
        self.ignored_patterns = load_ignore_patterns(self.project_path)

    def _run_scanner(self, tool_name: str, run_fn) -> List[Dict]:
        """Run one scanner and capture tool-specific errors."""
        try:
            self.scan_errors.pop(tool_name, None)
            return run_fn()
        except Exception as exc:
            self.scan_errors[tool_name] = str(exc)
            return []

    def run_trivy(self) -> List[Dict]:
        """Run Trivy vulnerability scanner"""
        scanner = TrivyScanner(self.project_path)
        return self._run_scanner(
            "trivy",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )
    
    def run_semgrep(self) -> List[Dict]:
        """Run Semgrep SAST scanner"""
        scanner = SemgrepScanner(self.project_path)
        return self._run_scanner(
            "semgrep",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )
    
    def run_gitleaks(self) -> List[Dict]:
        """Run Gitleaks secret scanner"""
        scanner = GitleaksScanner(self.project_path)
        return self._run_scanner(
            "gitleaks",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )

    def run_bandit(self) -> List[Dict]:
        """Run Bandit Python SAST scanner."""
        scanner = BanditScanner(self.project_path)
        return self._run_scanner("bandit", scanner.scan)

    def run_detect_secrets(self) -> List[Dict]:
        scanner = DetectSecretsScanner(self.project_path)
        return self._run_scanner(
            "detect-secrets",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )

    def run_checkov(self) -> List[Dict]:
        scanner = CheckovScanner(self.project_path)
        return self._run_scanner(
            "checkov",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )

    def run_grype(self) -> List[Dict]:
        scanner = GrypeScanner(self.project_path)
        return self._run_scanner(
            "grype",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )

    def run_osv_scanner(self) -> List[Dict]:
        scanner = OSVScanner(self.project_path)
        return self._run_scanner(
            "osv-scanner",
            lambda: scanner.scan(ignored_patterns=self.ignored_patterns),
        )

    def run_tool(self, tool_name: str) -> List[Dict]:
        dispatch = {
            "trivy": self.run_trivy,
            "semgrep": self.run_semgrep,
            "gitleaks": self.run_gitleaks,
            "bandit": self.run_bandit,
            "detect-secrets": self.run_detect_secrets,
            "checkov": self.run_checkov,
            "grype": self.run_grype,
            "osv-scanner": self.run_osv_scanner,
        }
        if tool_name not in dispatch:
            raise ValueError(f"Unknown tool: {tool_name}")
        return dispatch[tool_name]()

    def get_scan_plan(self, online: bool) -> List[str]:
        if online:
            return list(self.ALL_TOOLS)
        return [t for t in self.ALL_TOOLS if t not in self.ONLINE_REQUIRED_TOOLS]
    
    def scan_all_parallel(self) -> Dict:
        """Run all scanners in parallel for speed"""
        start_time = time.time()
        self.scan_errors = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.ALL_TOOLS)) as executor:
            futures = {executor.submit(self.run_tool, tool): tool for tool in self.ALL_TOOLS}
            for future, tool in futures.items():
                self.results[tool] = future.result()
        
        self.scan_duration = time.time() - start_time
        return self.results

    def get_all_findings(self, include_ignored: bool = False) -> List[Dict]:
        """Get flattened list of all findings with enriched snippets"""
        all_findings = []
        for tool, findings in self.results.items():
            all_findings.extend(findings)
            
        self._enrich_code_snippets(all_findings)
        
        if not include_ignored:
            # Filter out ignored findings
            all_findings = [f for f in all_findings if not self.fp_manager.is_ignored(f)]
            
        return all_findings
        
    def _enrich_code_snippets(self, findings: List[Dict]):
        """Ensure every finding has the actual code line"""
        for f in findings:
            # If snippet is missing or generic (like 'requires login'), read the file
            snippet = f.get("code_snippet") or f.get("code")
            if not snippet or len(snippet) < 3 or "login" in str(snippet).lower():
                try:
                    file_path = f.get("file")
                    if not file_path:
                        continue
                        
                    # Handle both absolute and relative paths
                    full_path = self.project_path / file_path
                    if not full_path.exists():
                        # Maybe it is already absolute?
                        full_path = Path(file_path)
                        
                    if full_path.exists() and full_path.is_file():
                        with open(full_path, 'r', errors='ignore') as file:
                            lines = file.readlines()
                            line_num = int(f.get("line", 1))
                            if 0 < line_num <= len(lines):
                                f["code_snippet"] = lines[line_num - 1].strip()
                except Exception:
                    pass # Keep original if reading fails
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        active_findings = self.get_all_findings(include_ignored=False)
        # We can detect suppressed count by differencing, or direct query
        # Currently simple way:
        total_raw = sum(len(r) for r in self.results.values())
        suppressed = total_raw - len(active_findings)
        
        return {
            "total_findings": len(active_findings),
            "suppressed_findings": suppressed,
            "by_tool": {
                "trivy": len([f for f in active_findings if f.get("tool") == "trivy"]),
                "semgrep": len([f for f in active_findings if f.get("tool") == "semgrep"]),
                "gitleaks": len([f for f in active_findings if f.get("tool") == "gitleaks"]),
                "bandit": len([f for f in active_findings if f.get("tool") == "bandit"]),
                "detect-secrets": len([f for f in active_findings if f.get("tool") == "detect-secrets"]),
                "checkov": len([f for f in active_findings if f.get("tool") == "checkov"]),
                "grype": len([f for f in active_findings if f.get("tool") == "grype"]),
                "osv-scanner": len([f for f in active_findings if f.get("tool") == "osv-scanner"]),
            },
            "by_severity": {
                "critical": sum(1 for f in active_findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in active_findings if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in active_findings if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in active_findings if f.get("severity") == "LOW")
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
    print(f"   - Bandit: {summary['by_tool']['bandit']}")
    print(f"   Duration: {summary['scan_duration_seconds']}s")
    print(f"\n   Severity breakdown:")
    print(f"   🔴 Critical: {summary['by_severity']['critical']}")
    print(f"   🟠 High: {summary['by_severity']['high']}")
    print(f"   🟡 Medium: {summary['by_severity']['medium']}")
    print(f"   🟢 Low: {summary['by_severity']['low']}")
