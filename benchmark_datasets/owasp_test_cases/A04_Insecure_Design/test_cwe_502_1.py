"""CWE-502: Insecure Deserialization - VULNERABLE"""
import pickle
from flask import Flask, request
app = Flask(__name__)

@app.route('/load')
def load():
    data = request.get_data()
    obj = pickle.loads(data)  # VULN: Pickle with untrusted data
    return str(obj)
