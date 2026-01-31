"""
Vulnerable code for CWE-862: Missing Authorization
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
    def admin_panel(): return get_all_users()
    return result

if __name__ == "__main__":
    app.run(debug=True)
