"""
Emerging 2024 Threat: CLOUD-001
Exposed Kubernetes Secret
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
    k8s_secret = base64.b64decode(env['K8S_SECRET'])

