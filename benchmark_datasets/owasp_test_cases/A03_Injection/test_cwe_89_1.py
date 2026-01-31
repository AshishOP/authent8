"""CWE-89: SQL Injection - VULNERABLE"""
import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    query = f"SELECT * FROM users WHERE username = '{user}'"  # VULN
    cursor.execute(query)
