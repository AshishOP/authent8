#!/usr/bin/env python3
"""
Debug script to test GitHub Models API connection
"""
import os
from openai import OpenAI

# Load from .env
from pathlib import Path
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#') and '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

print("=" * 60)
print("🔍 Testing GitHub Models API Connection")
print("=" * 60)

# Check for token
github_token = os.getenv("GITHUB_TOKEN")
openai_key = os.getenv("OPENAI_API_KEY")

print(f"\n📋 Environment Check:")
print(f"  GITHUB_TOKEN: {'✅ Found' if github_token else '❌ Not found'}")
if github_token:
    print(f"    Value: {github_token[:10]}...{github_token[-4:]}")
print(f"  OPENAI_API_KEY: {'✅ Found' if openai_key else '❌ Not found'}")

if not github_token and not openai_key:
    print("\n❌ No API keys found! Please set GITHUB_TOKEN or OPENAI_API_KEY in .env")
    exit(1)

# Try GitHub Models API
if github_token:
    print("\n🔄 Testing GitHub Models API...")
    try:
        client = OpenAI(
            api_key=github_token,
            base_url="https://models.inference.ai.azure.com"
        )
        
        print("  Sending test request to GPT-4o...")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say 'Hello from GitHub Models!' in exactly 5 words."}
            ],
            max_tokens=20,
            temperature=0.1
        )
        
        result = response.choices[0].message.content
        print(f"\n✅ SUCCESS! GitHub Models API is working!")
        print(f"  Response: {result}")
        print(f"  Model used: {response.model}")
        
    except Exception as e:
        print(f"\n❌ GitHub Models API Error:")
        print(f"  {type(e).__name__}: {str(e)}")
        print(f"\n💡 Common issues:")
        print(f"  1. Token needs to be from github.com/settings/tokens")
        print(f"  2. Make sure you have access to GitHub Models")
        print(f"  3. Go to: https://github.com/marketplace/models")

# Try OpenAI API
if openai_key:
    print("\n🔄 Testing OpenAI API...")
    try:
        client = OpenAI(api_key=openai_key)
        
        print("  Sending test request to GPT-4o...")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say 'Hello from OpenAI!' in exactly 4 words."}
            ],
            max_tokens=20,
            temperature=0.1
        )
        
        result = response.choices[0].message.content
        print(f"\n✅ SUCCESS! OpenAI API is working!")
        print(f"  Response: {result}")
        print(f"  Model used: {response.model}")
        
    except Exception as e:
        print(f"\n❌ OpenAI API Error:")
        print(f"  {type(e).__name__}: {str(e)}")

print("\n" + "=" * 60)
print("Debug test complete!")
print("=" * 60)
