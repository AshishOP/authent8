"""
Vulnerable code for CWE-352: CSRF
OWASP Category: A01
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
    # No CSRF token validation
@app.route('/transfer', methods=['POST'])
def transfer(): pass
    return result

if __name__ == "__main__":
    app.run(debug=True)
