"""CWE-95: Code Injection - VULNERABLE"""
from flask import Flask, request
app = Flask(__name__)

@app.route('/calc')
def calculate():
    expr = request.args.get('expr')
    result = eval(expr)  # VULN: eval with user input
    return str(result)
