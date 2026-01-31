#!/usr/bin/env python3
"""
Test AI validator directly with environment loading
"""
import os
import sys
from pathlib import Path

# Load .env file
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    print("📋 Loading .env file...")
    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#') and '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value
                if 'TOKEN' in key or 'KEY' in key:
                    print(f"  Set {key}: {value[:10]}...{value[-4:]}")

# Now import and test
sys.path.insert(0, str(Path(__file__).parent))
from core.ai_validator import AIValidator

print("\n🔄 Testing AIValidator class...")
print(f"  GITHUB_TOKEN in env: {bool(os.getenv('GITHUB_TOKEN'))}")
print(f"  OPENAI_API_KEY in env: {bool(os.getenv('OPENAI_API_KEY'))}")

# Create validator
validator = AIValidator()

print(f"\n🔍 Validator initialized:")
print(f"  API key set: {bool(validator.api_key)}")
if validator.api_key:
    print(f"  API key value: {validator.api_key[:10]}...{validator.api_key[-4:]}")
print(f"  Base URL: {validator.base_url}")
print(f"  Client created: {bool(validator.client)}")

# Test with a simple finding
if validator.client:
    print("\n🧪 Testing with a sample finding...")
    test_finding = [{
        "tool": "semgrep",
        "type": "sast",
        "severity": "HIGH",
        "rule_id": "test-rule",
        "message": "Test SQL injection",
        "file": "test.py",
        "line": 10
    }]
    
    try:
        result = validator.validate_findings(test_finding)
        print(f"✅ SUCCESS! AI validation worked!")
        print(f"  Result: {result[0].get('ai_reasoning', 'No reasoning')}")
        print(f"  False positive: {result[0].get('is_false_positive', False)}")
        print(f"  Confidence: {result[0].get('ai_confidence', 0)}%")
    except Exception as e:
        print(f"❌ FAILED: {e}")
else:
    print("\n❌ No client created - validator not initialized properly")
