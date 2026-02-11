"""Grype scanner wrapper for Authent8."""

import json
import subprocess
from pathlib import Path
from typing import Dict, List


class GrypeScanner:
    """Wrapper for Grype vulnerability scanner."""

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        cmd = [
            "grype",
            f"dir:{self.project_path}",
            "-o",
            "json",
            "--quiet",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("grype not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("grype timed out after 600s") from exc

        # Grype often returns 2 when vulnerabilities are found.
        if result.returncode not in [0, 1, 2]:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"grype failed: {err[:300]}")

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("grype returned invalid JSON output") from exc

        return self._parse_results(data)

    def _parse_results(self, data: Dict) -> List[Dict]:
        findings: List[Dict] = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            severity = str(vuln.get("severity", "MEDIUM")).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = "MEDIUM"
            findings.append(
                {
                    "tool": "grype",
                    "type": "vulnerability",
                    "severity": severity,
                    "rule_id": vuln.get("id", ""),
                    "title": vuln.get("id", "")[:200],
                    "description": vuln.get("description", "")[:500],
                    "message": f"{artifact.get('name', 'package')} vulnerable: {vuln.get('id', '')}"[:200],
                    "file": artifact.get("locations", [{}])[0].get("path", "dependencies"),
                    "line": 0,
                    "package": artifact.get("name", ""),
                    "fixed_version": (vuln.get("fix", {}) or {}).get("versions", [""])[0],
                    "is_false_positive": False,
                    "ai_confidence": 0,
                    "fix_suggestion": "",
                    "ai_reasoning": "",
                    "validated": False,
                }
            )
        return findings
