"""
Vulnerable code for CWE-476: NULL Pointer Dereference
OWASP Category: A04
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
    result.strip()
    return result

if __name__ == "__main__":
    app.run(debug=True)
