"""CWE-327: Weak Hash SHA1 - VULNERABLE"""
import hashlib

def hash_token(token):
    # VULN: SHA1 is deprecated for security
    return hashlib.sha1(token.encode()).hexdigest()  # VULN
