"""
Emerging 2024 Threat: SEC-002
Private Key in Code
"""
from flask import Flask, request
import os
import pickle
import jwt
import requests
import base64

app = Flask(__name__)

def vulnerable():
    user_input = request.args.get('input')
    PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----'''

