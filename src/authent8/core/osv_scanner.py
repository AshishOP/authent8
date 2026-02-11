"""OSV-Scanner wrapper for Authent8."""

import json
import subprocess
from pathlib import Path
from typing import Dict, List


class OSVScanner:
    """Wrapper for OSV-Scanner vulnerability scanner."""

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        cmd = [
            "osv-scanner",
            "scan",
            "source",
            "-r",
            str(self.project_path),
            "--format",
            "json",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("osv-scanner not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("osv-scanner timed out after 600s") from exc

        if result.returncode not in [0, 1]:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"osv-scanner failed: {err[:300]}")

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("osv-scanner returned invalid JSON output") from exc

        return self._parse_results(data)

    def _parse_results(self, data: Dict) -> List[Dict]:
        findings: List[Dict] = []
        # Handles common OSV JSON shapes.
        blocks = data.get("results", [])
        for block in blocks:
            packages = block.get("packages", []) or block.get("results", [])
            for pkg in packages:
                vulns = pkg.get("vulnerabilities", []) or pkg.get("vulns", [])
                for vuln in vulns:
                    severity = "HIGH"
                    findings.append(
                        {
                            "tool": "osv-scanner",
                            "type": "vulnerability",
                            "severity": severity,
                            "rule_id": vuln.get("id", ""),
                            "title": vuln.get("summary", vuln.get("id", ""))[:200],
                            "description": vuln.get("details", vuln.get("summary", ""))[:500],
                            "message": f"Dependency vulnerability: {vuln.get('id', '')}"[:200],
                            "file": block.get("source", "dependencies"),
                            "line": 0,
                            "package": (pkg.get("package", {}) or {}).get("name", pkg.get("name", "")),
                            "fixed_version": "",
                            "is_false_positive": False,
                            "ai_confidence": 0,
                            "fix_suggestion": "",
                            "ai_reasoning": "",
                            "validated": False,
                        }
                    )
        return findings
