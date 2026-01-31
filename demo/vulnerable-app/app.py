"""
Vulnerable Flask Application for Testing Authent8
This app intentionally contains multiple security vulnerabilities for demonstration.
"""
import sqlite3
from flask import Flask, request, render_template_string
import pickle
import hashlib
import os

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secrets (Gitleaks will catch)
API_KEY = "sk-1234567890abcdef"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin123"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# VULNERABILITY 2: SQL Injection (Semgrep will catch)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Dangerous: Direct string interpolation in SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection vulnerability
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return "Login successful!"
    return "Login failed!"

# VULNERABILITY 3: Command Injection (Semgrep will catch)
@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    # Dangerous: Using shell=True with user input
    os.system(f"ping -c 1 {host}")
    return f"Pinged {host}"

# VULNERABILITY 4: Code Injection via eval() (Semgrep will catch)
@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.form.get('expression', '')
    # Dangerous: eval() can execute arbitrary code
    result = eval(expression)
    return str(result)

# VULNERABILITY 5: Pickle deserialization (Semgrep will catch)
@app.route('/load', methods=['POST'])
def load_data():
    data = request.form.get('data', '')
    # Dangerous: Unpickling untrusted data
    obj = pickle.loads(data.encode())
    return str(obj)

# VULNERABILITY 6: Weak cryptography (Semgrep will catch)
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password', '')
    # Dangerous: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed

# VULNERABILITY 7: XSS vulnerability (Semgrep will catch)
@app.route('/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'Guest')
    # Dangerous: Rendering user input without escaping
    return render_template_string(f"<h1>Hello {name}!</h1>")

# VULNERABILITY 8: Path traversal (Semgrep will catch)
@app.route('/read', methods=['GET'])
def read_file():
    filename = request.args.get('file', '')
    # Dangerous: No validation of file path
    with open(filename, 'r') as f:
        content = f.read()
    return content

# VULNERABILITY 9: Insecure random (Semgrep will catch)
@app.route('/token', methods=['GET'])
def generate_token():
    import random
    # Dangerous: Using random instead of secrets for tokens
    token = ''.join(random.choices('0123456789abcdef', k=32))
    return token

# VULNERABILITY 10: Debug mode in production (Semgrep will catch)
if __name__ == '__main__':
    # Dangerous: debug=True exposes sensitive information
    app.run(host='0.0.0.0', port=5000, debug=True)
