"""
Emerging 2024 Threat: WEB-001
Prototype Pollution
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
    obj.__proto__ = malicious

