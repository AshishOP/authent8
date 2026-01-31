"""
Vulnerable code for CWE-276: Incorrect Default Permissions
OWASP Category: A05
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
    os.chmod(filepath, 0o777)
    return result

if __name__ == "__main__":
    app.run(debug=True)
