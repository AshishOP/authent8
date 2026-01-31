"""
Vulnerable code for CWE-427: Uncontrolled Search Path
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
    import user_module
    return result

if __name__ == "__main__":
    app.run(debug=True)
