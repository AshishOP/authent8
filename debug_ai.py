#!/usr/bin/env python3
"""Debug AI validation"""
import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env
env_file = Path('.env')
print(f"Looking for .env at: {env_file.absolute()}")
print(f"Exists: {env_file.exists()}")

if env_file.exists():
    load_dotenv(env_file)
    
print()
print("=== Environment Variables ===")
api_key = os.getenv("OPENAI_API_KEY", "")
print(f"OPENAI_API_KEY: {api_key[:30]}..." if api_key else "OPENAI_API_KEY: NOT SET")
print(f"OPENAI_BASE_URL: {os.getenv('OPENAI_BASE_URL', 'NOT SET')}")
print(f"AI_MODEL: {os.getenv('AI_MODEL', 'NOT SET')}")
print(f"FASTROUTER_API_KEY: {os.getenv('FASTROUTER_API_KEY', 'NOT SET')}")

print()
print("=== Testing AIValidator ===")
from core.ai_validator import AIValidator
v = AIValidator()
print(f"API Key (exists): {bool(v.api_key)}")
print(f"API Key (first 30): {v.api_key[:30] if v.api_key else 'None'}...")
print(f"Base URL: {v.base_url}")
print(f"Model: {v.model}")
print(f"Client initialized: {v.client is not None}")

# Test a simple call
if v.client:
    print()
    print("=== Testing API Call ===")
    test_finding = [{
        "tool": "semgrep",
        "type": "sast",
        "severity": "HIGH",
        "rule_id": "sql-injection-test",
        "message": "SQL injection detected",
        "file": "test.py",
        "line": 10,
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
    }]
    
    try:
        result = v.validate_findings(test_finding)
        print(f"Result: {result}")
        if result and result[0].get("validated"):
            print("SUCCESS! AI validation working!")
        else:
            print("AI validation returned but no validation data")
    except Exception as e:
        print(f"Error: {e}")
