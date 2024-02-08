from flask import Blueprint
from flask import jsonify
from app.utilities.File import File
from app.utilities.Hex import Hex
from app.utilities.PlainTextResponse import PlainTextResponse
import os
from werkzeug.exceptions import InternalServerError, NotFound

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


rsa_low_public_exp_blueprint = Blueprint("rsa-low-public-exp", __name__)

DATA_FILE = os.path.join("app", "data", "rsa-low-public-exp.json")
DATA_DIRECTORY = os.path.join("app", "data")

AES_KEY_LENGTH_IN_HEXS = 32
AES_IV_LENGTH_IN_HEXS = 32
AES_BLOCK_SIZE_IN_HEXS = 32

@rsa_low_public_exp_blueprint.route("/rsa-low-public-exp/<task_id>/params", strict_slashes=False, methods=["GET"])
def params(task_id):
    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: aa08] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    pem = task.get("pem", None)

    if not pem:
        raise InternalServerError(description="[Code: aa09] Corrupted list of API keys. Couldn't proceed.")

    pem_file_path = os.path.join(DATA_DIRECTORY, pem)
    #print("PEM: " + pem_file_path)
    if not os.path.exists(pem_file_path):
        raise InternalServerError(description="[Code: aaee] PEM file is missing.")

    try:
        with open(pem_file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password = None)
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        #print("ERROR: " + str(e))
        raise InternalServerError(description="[Code: af5e] Unknown error happened while loading PEM file.")

    return PlainTextResponse(response=public_pem.decode("utf-8") )

@rsa_low_public_exp_blueprint.route("/rsa-low-public-exp/<task_id>/cipher", strict_slashes=False, methods=["GET"])
def cipher(task_id):
    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: aa08] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    pem = task.get("pem", None)
    message = task.get("message", None)
    key = task.get("key", None)
    iv = task.get("iv", None)
    pem_file_path = os.path.join(DATA_DIRECTORY, pem)

    if not pem:
        raise InternalServerError(description="[Code: aa09] Corrupted list of API keys. Couldn't proceed.")
    if not message:
        raise InternalServerError(description="[Code: aa0a] Message is missing.")
    if not key:
        raise InternalServerError(description="[Code: aa0b] Key is missing.")
    if len(key) != AES_KEY_LENGTH_IN_HEXS:
        raise InternalServerError(description="[Code: aa0c] Bad key size.")
    if not iv:
        raise InternalServerError(description="[Code: aa0d] IV is missing.")
    if len(iv) != AES_IV_LENGTH_IN_HEXS:
        raise InternalServerError(description="[Code: aa0e] Bad IV size.")
    if not os.path.exists(pem_file_path):
        raise InternalServerError(description="[Code: aaef] PEM file is missing.")

    iv_key_hex = iv + key
    iv_key_int = int(iv_key_hex, 16)

    try:
        with open(pem_file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password = None)
        public_numbers = private_key.public_key().public_numbers()

        N = public_numbers.n
        e = public_numbers.e

        key_encrypted = pow(iv_key_int, e, N)
        key_encrypted_hex = Hex.int2hex(key_encrypted)

        padder = padding.PKCS7(4 * AES_BLOCK_SIZE_IN_HEXS).padder()
        padded_data = padder.update(message.encode("ascii")) + padder.finalize()
        print(padded_data)

        cipher = Cipher(algorithms.AES(bytearray.fromhex(key)), modes.CBC(bytearray.fromhex(iv)))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    except Exception as e:
        print("ERROR: " + str(e))
        raise InternalServerError(description="[Code: aaff] Unknown error.")

    return jsonify({"key_encrypted": key_encrypted_hex, "ciphertext": ciphertext.hex() })
