import json
import hashlib
from pathlib import Path
from typing import Dict, List, Set

class FalsePositiveManager:
    """Manages suppressed security findings via a local .authent8_fp.json file"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.fp_file = project_path / ".authent8_fp.json"
        self.ignored_hashes: Set[str] = set()
        self.ignored_findings: List[Dict] = []
        self._load()

    def _compute_hash(self, finding: Dict) -> str:
        """Generate a stable hash for a finding"""
        # We use rule_id + file_path + normalized code snippet
        # If snippet is missing, use line number (brittle but fallback)
        rule = finding.get("rule_id", "unknown")
        file = finding.get("file", "unknown")
        
        # Normalize code: remove all whitespace
        code = finding.get("code_snippet") or finding.get("code") or ""
        if code:
            # Robust signature: file + rule + code content
            signature = "".join(code.split())
        else:
            # Fallback to line number if no code context
            signature = str(finding.get("line", 0))
            
        raw = f"{rule}|{file}|{signature}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _load(self):
        """Load false positives from file"""
        if self.fp_file.exists():
            try:
                with open(self.fp_file, 'r') as f:
                    data = json.load(f)
                    self.ignored_hashes = set(data.get("hashes", []))
                    self.ignored_findings = data.get("findings", [])
            except Exception:
                self.ignored_hashes = set()
                self.ignored_findings = []

    def save(self):
        """Save false positives to file"""
        data = {
            "hashes": list(self.ignored_hashes),
            "findings": self.ignored_findings
        }
        with open(self.fp_file, 'w') as f:
            json.dump(data, f, indent=2)

    def add(self, finding: Dict):
        """Mark a finding as false positive"""
        fp_hash = self._compute_hash(finding)
        if fp_hash not in self.ignored_hashes:
            self.ignored_hashes.add(fp_hash)
            # Store metadata for management UI (only keep essential fields to save space)
            stored_data = {
                "fp_hash": fp_hash,
                "rule_id": finding.get("rule_id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "severity": finding.get("severity"),
                "code": finding.get("code_snippet") or finding.get("code")
            }
            self.ignored_findings.append(stored_data)
            self.save()

    def remove(self, fp_hash: str):
        """Unmark a false positive"""
        if fp_hash in self.ignored_hashes:
            self.ignored_hashes.remove(fp_hash)
            self.ignored_findings = [f for f in self.ignored_findings if f.get("fp_hash") != fp_hash]
            self.save()

    def is_ignored(self, finding: Dict) -> bool:
        """Check if a finding should be suppressed"""
        return self._compute_hash(finding) in self.ignored_hashes
