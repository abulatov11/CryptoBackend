from flask import Blueprint
from flask import jsonify
from app.utilities.File import File
from app.utilities.Hash import MyHash
from app.utilities.Hex import Hex
import os
from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

rsa_blueprint = Blueprint("rsa", __name__)

DATA_FILE = os.path.join("app", "data", "rsa.json")

def pad_message(message_hex, max_message_size_in_bytes):
    #message_hex = Hex.string2hex(message)
    if len(message_hex) > 2 * max_message_size_in_bytes:
        raise BadRequest(description="[Code: 65ca] Message cannot exceed ")
    message_int = int(message_hex, 16)


@rsa_blueprint.route("/authenticate/<task_id>/<data>", strict_slashes=False, methods=["GET"])
def index(task_id, data):
    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    data = Hex.filter(data)

    if not tasks:
        raise InternalServerError(description="[Code: 6ee8] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    try:
        p = int(task.get("p", None), 16)
        q = int(task.get("q", None), 16)
        e = int(task.get("e", None), 16)
        key_size = int(task.get("key_size", None))
    except:
        pass

    if (not p) or (not q) or (not e) or not(key_size):
        raise InternalServerError(description="[Code: 6e23] Corrupted list of API keys. Couldn't proceed.")


    message = "hello"
    message_hex = Hex.string2hex(message)
    message_int = int(message_hex, 16)

    output = {
        "message": message,
        "message_hex": message_hex,
        "message_int": str(message_int)
    }

    return jsonify(output)