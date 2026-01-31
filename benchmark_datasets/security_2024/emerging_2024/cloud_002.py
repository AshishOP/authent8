"""
Emerging 2024 Threat: CLOUD-002
IAM Misconfiguration
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
    iam_policy = {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}

