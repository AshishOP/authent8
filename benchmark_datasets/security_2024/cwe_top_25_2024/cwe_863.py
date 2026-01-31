"""
Vulnerable code for CWE-863: Incorrect Authorization
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
    if user.id == request.user_id: allow()
    return result

if __name__ == "__main__":
    app.run(debug=True)
