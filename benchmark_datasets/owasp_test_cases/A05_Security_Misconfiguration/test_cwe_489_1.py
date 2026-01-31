"""CWE-489: Debug Mode - VULNERABLE"""
from flask import Flask
app = Flask(__name__)

if __name__ == '__main__':
    # VULN: Debug mode in production
    app.run(host='0.0.0.0', debug=True)  # VULN
