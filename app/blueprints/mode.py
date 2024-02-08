from flask import Blueprint
from flask import request, jsonify, current_app
from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound
from app.utilities.OpenSSL import OpenSSL
from app.utilities.File import File
import json
import string
import binascii
import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# constants needed for the blueprint
DATA_FILE = os.path.join("app", "data", "mode.json")


mode_blueprint = Blueprint("mode", __name__)

MAX_REQUEST_SIZE_IN_BYTES = 100 * 1024 # Maximum request size is about 100kB
MAX_IV_SIZE_IN_BYTES = 16 
ASSIGNMENT_DATA_FILE = "assignment2.json"
HEXS = "0123456789abcdef"
VALID_CIPHERS = ["AES"]
VALID_MODES = ["CBC", "ECB", "CTR", "OFB", "CFB"]
CIPHERS_MAPPING = {
    "AES": {
        128: {
            "ECB": OpenSSL.AES128_ECB,
            "CBC": OpenSSL.AES128_CBC,
            "CTR": OpenSSL.AES128_CTR,
            "OFB": OpenSSL.AES128_OFB,
            "CFB": OpenSSL.AES128_CFB
        },
        192: {
            "ECB": OpenSSL.AES192_ECB,
            "CBC": OpenSSL.AES192_CBC,
            "CTR": OpenSSL.AES192_CTR,
            "OFB": OpenSSL.AES192_OFB,
            "CFB": OpenSSL.AES192_CFB
        },
        256: {
            "ECB": OpenSSL.AES256_ECB,
            "CBC": OpenSSL.AES256_CBC,
            "CTR": OpenSSL.AES256_CTR,
            "OFB": OpenSSL.AES256_OFB,
            "CFB": OpenSSL.AES256_CFB
        }
    }
}

tasks = {}

def is_spaced_hex(text):
    return all([(c == " " or c in string.hexdigits) for c in text])

def validate_request_v1(req):
    if req.is_json:
        
        if req.content_length >= MAX_REQUEST_SIZE_IN_BYTES:
            raise RequestEntityTooLarge()
        
        try:
            data = json.loads(req.data)
        except Exception:
            raise BadRequest(description="[Code: 6771] A malformed JSON was submitted.")
    elif req.method == "GET":
        try:
            data = {
                "iv": req.args.get("iv", ""),
                "text": req.args.get("text", "")
            }
        except Exception:
            raise BadRequest("[Code: 1e99] iv and/or text arguments are required.")
    else:
        raise BadRequest("[Code: afe1] Text and iv are expected. None were passed.")
    
    if not data.get("iv", "").strip():
        raise BadRequest(description="[Code: 3a17] Field 'iv' is missing.")
    if not data.get("text", "").strip():
        raise BadRequest(description="[Code: f1fb] Field 'text' is missing.")

    if not is_spaced_hex(data["iv"]):
        raise BadRequest(description="[Code: 2488] Only HEXs and whitespaces are allowed in 'iv'.")
    if not is_spaced_hex(data["text"]):
        raise BadRequest(description="[Code: 0c19] Only HEXs and whitespaces are allowed in 'text'.")

    data["iv"] = "".join(filter(lambda c: c in string.hexdigits, data.get("iv", "").strip())).lower()
    data["text"] = "".join(filter(lambda c: c in string.hexdigits, data.get("text", "").strip())).lower()

    if not data.get("iv", ""):
        raise BadRequest(description="[Code: 3e45] Submitted 'iv' does not contain HEX digits.")
    if not data.get("text", ""):
        raise BadRequest(description="[Code: fcab] Submitted 'text' does not contain HEX digits.")

    if len(data["iv"]) & 0x01:    
        raise BadRequest(description="[Code: 7648] Field 'iv' must contain an even number of HEX digits.")
    if len(data["text"]) & 0x01:    
        raise BadRequest(description="[Code: 6386] Field 'text' must contain an even number of HEX digits.")
    
    if len(data["iv"]) > 2*MAX_IV_SIZE_IN_BYTES:
        raise BadRequest(description="Field 'iv' cannot have more than %d HEX digits." % (2*MAX_IV_SIZE_IN_BYTES))
    
    return data

@mode_blueprint.route("/mode/<task_id>", strict_slashes=False, methods=["POST", "GET"])
def mode_index(task_id):
    
    ciphertext = None
    task_id = str(task_id)

    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: df39] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks[task_id]
    cipher = task.get("cipher", None)
    mode = task.get("mode", None)
    key_size = int(task.get("key-size", 0))
    key = task.get("key", None)
    padding = task.get("padding", False)

    data = validate_request_v1(request)
    iv = data["iv"]
    text = data["text"]
    
    if padding:
        last_block_length = int((len(text) % 32) / 2)
        symbol = hex(16 - last_block_length).replace("0x", "")
        symbol = ("0" + symbol) if len(symbol) == 1 else symbol
        text += symbol * (16 - last_block_length)

    if not key_size:
        raise InternalServerError(description="[Code: b942] Corrupted information about cipher's key length. Could not proceed.")
    if not key:
        key = "".join(random.choices(HEXS, k=int(int(key_size)/4)))
    
    cipher_id = CIPHERS_MAPPING.get(cipher.upper(), {}).get(key_size, {}).get(mode.upper(), None)
    if not cipher_id:
        # If cipher wasn't found among the valid ones, apply "randomized" cipher, i.e.
        # simply replace each HEX in the input plaintext with a random digit
        random.seed(key + iv)
        ciphertext = "".join(random.choices(HEXS, k=len(text)))
    else:
        # otherwise, apply a normal cipher specified in the assignment2.json under
        # the input task_id key
        try:
            openssl = OpenSSL(iv=iv, plaintext=text, key=key, cipher=cipher_id, is_hex_plaintext=True)
            ciphertext = openssl.encrypt()
        except Exception as e:
            #print(str(e))
            pass
    
    if not ciphertext:
        raise InternalServerError(description="[Code: 1fc0] Some error occurred during encryption.")

    return jsonify({"ciphertext": ciphertext})