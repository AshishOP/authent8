"""
Emerging 2024 Threat: SUPPLY-001
Dependency Confusion
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
    # requirements.txt with internal package name

