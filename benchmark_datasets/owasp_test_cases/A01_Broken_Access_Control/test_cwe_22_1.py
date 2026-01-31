"""CWE-22: Path Traversal - VULNERABLE"""
from flask import Flask, request
app = Flask(__name__)

@app.route('/read')
def read_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:  # VULN: Path traversal
        return f.read()
