"""detect-secrets scanner wrapper for Authent8."""

import json
import subprocess
from pathlib import Path
from typing import Dict, List


class DetectSecretsScanner:
    """Wrapper for detect-secrets."""

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def scan(self, ignored_patterns: List[str] = None) -> List[Dict]:
        cmd = [
            "detect-secrets",
            "scan",
            "--all-files",
            str(self.project_path),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("detect-secrets not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("detect-secrets timed out after 300s") from exc

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise RuntimeError(f"detect-secrets failed: {err[:300]}")

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("detect-secrets returned invalid JSON output") from exc

        return self._parse_results(data)

    def _parse_results(self, data: Dict) -> List[Dict]:
        findings: List[Dict] = []
        results = data.get("results", {})
        for file_path, secrets in results.items():
            for item in secrets or []:
                findings.append(
                    {
                        "tool": "detect-secrets",
                        "type": "secret",
                        "severity": "CRITICAL",
                        "rule_id": item.get("type", "secret"),
                        "title": f"Potential secret detected ({item.get('type', 'unknown')})",
                        "description": "Potential secret detected by detect-secrets",
                        "message": f"Potential secret detected: {item.get('type', 'unknown')}",
                        "file": file_path,
                        "line": item.get("line_number", 0),
                        "code_snippet": "",
                        "is_false_positive": False,
                        "ai_confidence": 0,
                        "fix_suggestion": "",
                        "ai_reasoning": "",
                        "validated": False,
                    }
                )
        return findings
