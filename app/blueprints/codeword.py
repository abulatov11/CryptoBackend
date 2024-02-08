from flask import Blueprint
from flask import jsonify
from flask import current_app
from werkzeug.exceptions import InternalServerError, NotFound
from app.utilities.File import File
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# constants needed for the blueprint
DATA_FILE = os.path.join("app", "data", "codeword.json")
KEY_SIZE_IN_BYTES = 16

# blueprint definition
codeword_blueprint = Blueprint("codeword", __name__)

@codeword_blueprint.route("/codeword/<task_id>", strict_slashes=False, methods=["GET"])
def codeword_index(task_id):

    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: 3ee8bb91ffdb] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    if "codeword" not in tasks[task_id]:
        raise InternalServerError(description="[Code: f655a7dcbac0] Corrupted list of API keys. Couldn't proceed.")

    key = os.urandom(KEY_SIZE_IN_BYTES)
    codeword = tasks[task_id].get("codeword", None)

    try:
        algorithm = algorithms.ARC4(key)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(codeword.encode("ascii")) + encryptor.finalize()
    except Exception as e:
        raise InternalServerError(description="[Code: e69a47cf78f1] Error happened while encrypting the codeword.")

    output = {"codeword": binascii.hexlify(ciphertext).decode("utf-8")}

    if current_app.testing:
        output["original-codeword"] = codeword
        output["key"] = binascii.hexlify(key).decode("utf-8")

    return jsonify(output)


