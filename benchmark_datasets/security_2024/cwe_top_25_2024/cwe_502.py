"""
Vulnerable code for CWE-502: Insecure Deserialization
OWASP Category: A08
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
    pickle.loads(user_data)
    return result

if __name__ == "__main__":
    app.run(debug=True)
