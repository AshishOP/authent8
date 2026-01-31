"""
Vulnerable code for CWE-190: Integer Overflow
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
    result = big_num * big_num
    return result

if __name__ == "__main__":
    app.run(debug=True)
