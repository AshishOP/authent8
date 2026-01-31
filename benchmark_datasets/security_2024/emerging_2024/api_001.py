"""
Emerging 2024 Threat: API-001
Mass Assignment
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
    user.update(**request.json)

