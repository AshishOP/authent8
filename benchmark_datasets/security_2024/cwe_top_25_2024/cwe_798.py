"""
Vulnerable code for CWE-798: Hardcoded Credentials
OWASP Category: A02
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
    API_KEY = 'sk-secret123456789'
    return result

if __name__ == "__main__":
    app.run(debug=True)
