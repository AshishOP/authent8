"""
Emerging 2024 Threat: AI-002
LLM Data Leakage
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
    model.train(sensitive_data)

