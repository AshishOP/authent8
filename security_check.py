import os
import subprocess
import hashlib

# ==========================================
# 🚨 TRUE POSITIVES (Should be detected)
# ==========================================

# 1. Hardcoded Secrets (Gitleaks)
AWS_SECRET_KEY = "AKIA1234567890ABCDEF" 
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"

# 2. Command Injection (Semgrep)
def run_command(user_input):
    # DANGEROUS: Passing user input directly to shell
    os.system("echo " + user_input)
    subprocess.call(user_input, shell=True)

# 3. SQL Injection (Semgrep)
def get_user(user_id):
    # DANGEROUS: F-string SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    print(query)

# 4. Insecure Crypto (Semgrep/Bandit)
def weak_hash(password):
    # DANGEROUS: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# ==========================================
# ✅ FALSE POSITIVES (Should be ignored/validated)
# ==========================================

# 1. Example/Placeholder Secrets (Gitleaks often flags these)
EXAMPLE_API_KEY = "0000000000000000"
TEST_PASSWORD = "password123"

# 2. Safe Command Execution (Semgrep might flag, but it's safe)
def clear_screen():
    # SAFE: No user input
    os.system("clear")

# 3. MD5 for Checksums (Not security related)
def get_file_etag(content):
    # SAFE: MD5 is fine for non-cryptographic checksums
    return hashlib.md5(content).hexdigest()

# 4. Hardcoded "Password" in variable name
DB_PASSWORD_FIELD = "password_input_field_id"
