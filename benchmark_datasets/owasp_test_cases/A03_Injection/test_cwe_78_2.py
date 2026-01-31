"""CWE-78: Command Injection - VULNERABLE"""
import os
from flask import Flask, request
app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system(f"ping -c 1 {host}")  # VULN: Command injection
    return "done"
