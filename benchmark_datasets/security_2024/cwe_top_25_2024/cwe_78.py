"""
Vulnerable code for CWE-78: OS Command Injection
OWASP Category: A03
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
    os.system(f'ping {user_input}')
    return result

if __name__ == "__main__":
    app.run(debug=True)
