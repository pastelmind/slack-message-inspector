"""Flask-driven wrapper for main.py. Call with `flask run`."""

from flask import Flask, request
from main import on_request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def google_functions_endpoint():
    """Calls the Google Functions endpoint in `main.py`."""
    return on_request(request)
