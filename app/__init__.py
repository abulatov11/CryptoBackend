from flask import Flask, request, render_template, jsonify
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 120 * 1024 * 1024 # Maximum allowed request body is 120MB
app.config["UPLOAD_FOLDER"] = "app/tmp"
app.config["SECRET_KEY"] = "1e83572c4af8"

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    if "/api/" in request.path:
        return jsonify({
            "code": e.code,
            "error": str(e.description)
        }), e.code
    return e

@app.after_request
def after_request(response):
    response.headers.set("Server", "CryptoLab")
    return response

from app import routes