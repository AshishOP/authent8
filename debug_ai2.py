#!/usr/bin/env python3
"""Debug AI validation - trace the error"""
import os
import json
from dotenv import load_dotenv
from pathlib import Path

# Load .env
env_file = Path('.env')
load_dotenv(env_file)

api_key = os.getenv("OPENAI_API_KEY", "")
base_url = os.getenv("OPENAI_BASE_URL", "")
model = os.getenv("AI_MODEL", "gpt-4o")

print(f"API Key length: {len(api_key)}")
print(f"Base URL: {base_url}")
print(f"Model: {model}")

# Test API directly
from openai import OpenAI

client = OpenAI(
    api_key=api_key,
    base_url=base_url
)

print("\nSending test request...")

try:
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "Reply with exactly: {\"test\": true}"},
            {"role": "user", "content": "test"}
        ],
        temperature=0.1,
        max_tokens=50
    )
    print(f"Success! Response: {response.choices[0].message.content}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
