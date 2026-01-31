"""
Vulnerable code for CWE-306: Missing Auth Critical Function
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
    def delete_user(id): db.delete(id)
    return result

if __name__ == "__main__":
    app.run(debug=True)
