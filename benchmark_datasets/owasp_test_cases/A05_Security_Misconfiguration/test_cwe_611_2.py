"""CWE-611: XXE - VULNERABLE"""
from lxml import etree
from flask import Flask, request
app = Flask(__name__)

@app.route('/parse')
def parse():
    data = request.get_data()
    tree = etree.fromstring(data)  # VULN: XXE possible
    return str(tree)
