from authent8.core.ai_validator import AIValidator


def test_security_check_fixture_is_auto_ignored():
    validator = AIValidator(api_key="dummy")
    findings = [
        {
            "tool": "semgrep",
            "file": "security_check.py",
            "rule_id": "foo",
            "message": "bar",
            "code_snippet": "",
        }
    ]

    validator._apply_heuristics(findings)
    assert findings[0]["is_false_positive"] is True
    assert findings[0]["validated"] is True


def test_gitleaks_placeholder_in_test_file_is_auto_ignored():
    validator = AIValidator(api_key="dummy")
    findings = [
        {
            "tool": "gitleaks",
            "file": "tests/keys_test.py",
            "rule_id": "generic-api-key",
            "message": "Found test placeholder key",
            "code_snippet": "DUMMY_KEY = '12345'",
        }
    ]

    validator._apply_heuristics(findings)
    assert findings[0]["is_false_positive"] is True
    assert findings[0]["validated"] is True


def test_non_test_path_is_not_auto_ignored():
    validator = AIValidator(api_key="dummy")
    findings = [
        {
            "tool": "gitleaks",
            "file": "src/app.py",
            "rule_id": "generic-api-key",
            "message": "Hardcoded key found",
            "code_snippet": "API_KEY = 'supersecret'",
        }
    ]

    validator._apply_heuristics(findings)
    assert findings[0].get("validated") is not True
