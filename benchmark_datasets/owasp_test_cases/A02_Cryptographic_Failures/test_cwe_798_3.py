"""CWE-798: Hardcoded Credentials - VULNERABLE"""
import os

DB_PASSWORD = "admin123"  # VULN: Hardcoded password
API_KEY = "sk-1234567890abcdef"  # VULN: Hardcoded API key

def connect():
    return Database(password=DB_PASSWORD)
