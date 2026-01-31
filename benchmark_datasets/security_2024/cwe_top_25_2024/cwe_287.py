"""
Vulnerable code for CWE-287: Improper Authentication
OWASP Category: A07
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
    if password == stored_password: return True
    return result

if __name__ == "__main__":
    app.run(debug=True)
