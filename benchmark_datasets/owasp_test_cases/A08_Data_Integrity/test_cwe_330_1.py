"""CWE-330: Insecure Random - VULNERABLE"""
import random
import string

def generate_token():
    # VULN: random is not cryptographically secure
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))  # VULN
