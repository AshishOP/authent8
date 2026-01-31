"""CWE-639: IDOR - VULNERABLE"""
from flask import Flask, request, session
app = Flask(__name__)

@app.route('/user/<id>')
def get_user(id):
    # VULN: No authorization check - any user can access any profile
    user = db.query(f"SELECT * FROM users WHERE id = {id}")  # VULN
    return user
