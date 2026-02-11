"""Lightweight smoke checks for parser/orchestrator logic."""

from pathlib import Path

from authent8.core.bandit_scanner import BanditScanner
from authent8.core.checkov_scanner import CheckovScanner
from authent8.core.detect_secrets_scanner import DetectSecretsScanner
from authent8.core.gitleaks_scanner import GitleaksScanner
from authent8.core.grype_scanner import GrypeScanner
from authent8.core.osv_scanner import OSVScanner
from authent8.core.scanner_orchestrator import ScanOrchestrator
from authent8.core.semgrep_scanner import SemgrepScanner
from authent8.core.trivy_scanner import TrivyScanner


def main() -> None:
    orchestrator = ScanOrchestrator(".")
    online_plan = orchestrator.get_scan_plan(True)
    offline_plan = orchestrator.get_scan_plan(False)
    assert "trivy" in online_plan and "semgrep" in online_plan
    assert "grype" in online_plan and "osv-scanner" in online_plan
    assert "trivy" not in offline_plan and "semgrep" not in offline_plan
    assert "gitleaks" in offline_plan and "bandit" in offline_plan
    assert "detect-secrets" in offline_plan and "checkov" in offline_plan

    trivy = TrivyScanner(Path("."))
    assert len(
        trivy._parse_results(
            {
                "Results": [
                    {
                        "Target": "a.txt",
                        "Vulnerabilities": [
                            {
                                "Severity": "HIGH",
                                "Title": "vuln",
                                "Description": "desc",
                                "VulnerabilityID": "CVE-1",
                                "PkgName": "pkg",
                                "FixedVersion": "1.2.3",
                            }
                        ],
                        "Misconfigurations": [
                            {
                                "Severity": "MEDIUM",
                                "Title": "misconfig",
                                "Description": "desc",
                                "Message": "msg",
                                "ID": "MIS-1",
                            }
                        ],
                    }
                ]
            }
        )
    ) == 2

    semgrep = SemgrepScanner(Path("."))
    semgrep_result = semgrep._parse_results(
        {
            "results": [
                {
                    "check_id": "X",
                    "path": "app.py",
                    "start": {"line": 12},
                    "extra": {
                        "severity": "WARNING",
                        "message": "test msg",
                        "lines": "x=1",
                    },
                }
            ]
        }
    )
    assert len(semgrep_result) == 1 and semgrep_result[0]["severity"] == "MEDIUM"

    gitleaks = GitleaksScanner(Path("."))
    assert len(
        gitleaks._parse_results(
            [
                {
                    "RuleID": "generic-api-key",
                    "Description": "secret",
                    "File": "a.py",
                    "StartLine": 7,
                }
            ]
        )
    ) == 1

    bandit = BanditScanner(Path("."))
    bandit_result = bandit._parse_results(
        {
            "results": [
                {
                    "issue_severity": "LOW",
                    "test_id": "B101",
                    "issue_text": "assert used",
                    "filename": "src/a.py",
                    "line_number": 4,
                    "code": "assert x",
                }
            ]
        }
    )
    assert len(bandit_result) == 1 and bandit_result[0]["file"] == "src/a.py"

    detect_secrets = DetectSecretsScanner(Path("."))
    assert len(
        detect_secrets._parse_results(
            {"results": {"src/a.py": [{"type": "Secret Keyword", "line_number": 9}]}}
        )
    ) == 1

    checkov = CheckovScanner(Path("."))
    checkov_result = checkov._parse_results(
        {
            "results": {
                "failed_checks": [
                    {
                        "severity": "HIGH",
                        "check_id": "CKV_X",
                        "check_name": "bad config",
                        "file_path": "/main.tf",
                        "file_line_range": [3, 5],
                    }
                ]
            }
        }
    )
    assert len(checkov_result) == 1 and checkov_result[0]["line"] == 3

    grype = GrypeScanner(Path("."))
    grype_result = grype._parse_results(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2",
                        "severity": "High",
                        "description": "desc",
                        "fix": {"versions": ["2.0"]},
                    },
                    "artifact": {
                        "name": "libx",
                        "locations": [{"path": "requirements.txt"}],
                    },
                }
            ]
        }
    )
    assert len(grype_result) == 1 and grype_result[0]["fixed_version"] == "2.0"

    osv = OSVScanner(Path("."))
    osv_result = osv._parse_results(
        {
            "results": [
                {
                    "source": "requirements.txt",
                    "packages": [
                        {
                            "package": {"name": "flask"},
                            "vulnerabilities": [
                                {"id": "OSV-1", "summary": "sum", "details": "details"}
                            ],
                        }
                    ],
                }
            ]
        }
    )
    assert len(osv_result) == 1 and osv_result[0]["package"] == "flask"

    print("SMOKE_OK")


if __name__ == "__main__":
    main()
