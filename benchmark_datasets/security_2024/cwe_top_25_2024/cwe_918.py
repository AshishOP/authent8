"""
Vulnerable code for CWE-918: SSRF
OWASP Category: A10
"""
from flask import Flask, request, jsonify
import os
import subprocess
import pickle
import hashlib
import requests
from lxml import etree

app = Flask(__name__)

# Vulnerable code below:
def vulnerable_function(user_input):
    requests.get(user_provided_url)
    return result

if __name__ == "__main__":
    app.run(debug=True)
