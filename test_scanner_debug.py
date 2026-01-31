#!/usr/bin/env python3
"""Debug script to find root cause of scanner issues"""
import subprocess
import json
from pathlib import Path

print("=" * 60)
print("SEMGREP SCANNER DEBUG")
print("=" * 60)

# Test directory
test_dir = Path("benchmark_datasets/security_2024/cwe_top_25_2024")
print(f"\nTest directory: {test_dir}")
print(f"Exists: {test_dir.exists()}")

if test_dir.exists():
    files = list(test_dir.glob("*.py"))
    print(f"Python files: {len(files)}")
    for f in files[:3]:
        print(f"  - {f.name}")

# Test 1: Direct semgrep command
print("\n" + "=" * 60)
print("TEST 1: Direct semgrep command")
print("=" * 60)

cmd = [
    "semgrep",
    "--config", "p/security-audit",
    "--json",
    "--no-git-ignore",
    str(test_dir)
]
print(f"Command: {' '.join(cmd)}")

result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
print(f"Return code: {result.returncode}")
print(f"Stderr length: {len(result.stderr)}")
print(f"Stdout length: {len(result.stdout)}")

if result.stdout:
    try:
        data = json.loads(result.stdout)
        findings = data.get("results", [])
        print(f"Findings: {len(findings)}")
        for f in findings[:3]:
            print(f"  - {f.get('path')}: {f.get('check_id', '')[:50]}")
    except:
        print("Could not parse JSON")

# Test 2: Using our scanner class
print("\n" + "=" * 60)
print("TEST 2: Using SemgrepScanner class")
print("=" * 60)

from core.semgrep_scanner import SemgrepScanner

scanner = SemgrepScanner(test_dir)
print(f"Scanner path: {scanner.project_path}")

# Let's see the actual command
custom_rules = Path("config/custom_rules.yml")
print(f"Custom rules exist: {custom_rules.exists()}")

results = scanner.scan()
print(f"Results: {len(results)}")

for r in results[:3]:
    print(f"  - {r.get('file')}: {r.get('rule_id', '')[:50]}")

# Test 3: Check if custom_rules.yml is causing issues
print("\n" + "=" * 60)
print("TEST 3: Semgrep without custom rules")
print("=" * 60)

cmd2 = [
    "semgrep",
    "--config", "p/security-audit",
    "--json",
    "--quiet",
    "--no-git-ignore",
    str(test_dir)
]
print(f"Command: {' '.join(cmd2)}")

result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=120)
print(f"Return code: {result2.returncode}")

if result2.stdout:
    try:
        data2 = json.loads(result2.stdout)
        findings2 = data2.get("results", [])
        print(f"Findings: {len(findings2)}")
    except:
        print(f"Parse error. Stderr: {result2.stderr[:200]}")
