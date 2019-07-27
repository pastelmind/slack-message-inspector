"""Flask-driven wrapper for main.py. Call with `flask run`."""

from flask import Flask, request
from main import on_request

app = Flask(__name__)
# Matches observed behavior of Cloud Functions
app.url_map.strict_slashes = False

# Based on https://cloud.google.com/functions/docs/calling/http
ALLOWED_METHODS = ['POST', 'PUT', 'GET', 'DELETE', 'OPTIONS']

@app.route('/', methods=ALLOWED_METHODS)
@app.route('/<path:_>', methods=ALLOWED_METHODS)
def google_functions_endpoint(_=''):
    """Calls the Google Functions endpoint in `main.py`."""
    return on_request(request)
