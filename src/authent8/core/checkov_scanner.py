"""Checkov scanner wrapper for Authent8."""

import json
import subprocess
from pathlib import Path
from typing import Dict, List


class CheckovScanner:
    """Wrapper for Checkov IaC security scanner."""

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        cmd = [
            "checkov",
            "-d",
            str(self.project_path),
            "--output",
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
            raise RuntimeError("checkov not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("checkov timed out after 600s") from exc

        # Checkov may return non-zero when findings exist.
        if result.returncode not in [0, 1]:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"checkov failed: {err[:300]}")

        raw = result.stdout.strip()
        if not raw:
            return []

        # Prefer full JSON parse first.
        try:
            data = json.loads(raw)
            return self._parse_results(data)
        except json.JSONDecodeError:
            pass

        # Checkov may emit multiple JSON docs; parse line-by-line.
        findings: List[Dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.extend(self._parse_results(data))
        return findings

    def _parse_results(self, data: Dict) -> List[Dict]:
        findings: List[Dict] = []
        failed = data.get("results", {}).get("failed_checks", [])
        for item in failed:
            severity = str(item.get("severity", "MEDIUM")).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = "MEDIUM"
            findings.append(
                {
                    "tool": "checkov",
                    "type": "iac",
                    "severity": severity,
                    "rule_id": item.get("check_id", ""),
                    "title": item.get("check_name", "")[:200],
                    "description": item.get("check_name", "")[:500],
                    "message": item.get("check_name", "")[:200],
                    "file": item.get("file_path", ""),
                    "line": item.get("file_line_range", [0])[0] if item.get("file_line_range") else 0,
                    "code_snippet": "",
                    "is_false_positive": False,
                    "ai_confidence": 0,
                    "fix_suggestion": "",
                    "ai_reasoning": "",
                    "validated": False,
                }
            )
        return findings
