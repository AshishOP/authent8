"""
Vulnerable code for CWE-77: Command Injection
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
    subprocess.call(user_cmd, shell=True)
    return result

if __name__ == "__main__":
    app.run(debug=True)
