"""
Emerging 2024 Threat: API-003
Rate Limit Bypass
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
    # No rate limiting on auth endpoint

