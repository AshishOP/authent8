"""CWE-918: SSRF - VULNERABLE"""
import requests
from flask import Flask, request
app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)  # VULN: SSRF
    return response.text
