"""CWE-521: Weak Password Requirements - VULNERABLE"""
def validate_password(password):
    # VULN: Only checks length, no complexity
    if len(password) >= 4:  # VULN: Too weak
        return True
    return False
