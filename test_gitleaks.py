#!/usr/bin/env python3
from pathlib import Path
from core.gitleaks_scanner import GitleaksScanner

scanner = GitleaksScanner(Path('../tests/vulnerable-app'))
results = scanner.scan()
print(f'Found {len(results)} secrets')
for r in results:
    print(f"  Line {r['line']}: {r['secret_type']}")
