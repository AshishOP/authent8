"""CWE-327: Weak Cryptography - VULNERABLE"""
import hashlib

def hash_password(password):
    # VULN: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()  # VULN

def verify(password, hash):
    return hash_password(password) == hash
