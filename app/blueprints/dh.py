from flask import Blueprint
from flask import Response
from flask import jsonify
from app.utilities.File import File
from app.utilities.Hex import Hex
import os
import random
import textwrap
import binascii
from base64 import b64encode
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest, InternalServerError, NotFound
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

dh_blueprint = Blueprint("dh", __name__)

DATA_FILE = os.path.join("app", "data", "dh.json")

DH_PRIME_FIELD_NAME = "prime"
DH_GENERATOR_FIELD_NAME = "generator"
TEXT_FIELD_NAME = "text"

MAX_SECRET_LENGTH = 96
BLOCK_SIZE_IN_BITS = 128

PEM_HEADER = "-----BEGIN DH PARAMETERS-----"
PEM_FOOTER = "-----END DH PARAMETERS-----"

def create_pem(prime, generator):
    prime = Hex.filter(prime)
    generator = Hex.filter(generator)

    if len(prime) & 0x1:
        prime = "0" + prime
    if len(generator) & 0x1:
        generator = "0" + generator

    prime_size_in_bytes = int(len(prime) / 2)
    generator_size_in_bytes = int(len(generator) / 2)

    prime_size_in_bytes_hexed = hex(prime_size_in_bytes)[2:].zfill(2)
    generator_size_in_bytes_hexed = hex(generator_size_in_bytes)[2:].zfill(2)

    prime_part = "02" + prime_size_in_bytes_hexed + prime
    generator_part = "02" + generator_size_in_bytes_hexed + generator

    numbers_part = prime_part + generator_part
    numbers_part_size_in_bytes = int(len(numbers_part) / 2)
    numbers_part_size_in_bytes_hexed = hex(numbers_part_size_in_bytes)[2:].zfill(2)

    pem_hex_data = "30" + str(numbers_part_size_in_bytes_hexed) + numbers_part

    #print(pem_hex_data)

    pem_base64_data = b64encode(bytes.fromhex(pem_hex_data)).decode()
    pem = textwrap.wrap(pem_base64_data, width=64)

    pem.append(PEM_FOOTER)
    pem.insert(0, PEM_HEADER)

    return "\n".join(pem)

@dh_blueprint.route("/dh/<task_id>/params", strict_slashes=False, methods=["GET"])
def parameters(task_id):

    task_id = str(task_id).strip()
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: 5902] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    prime = task.get(DH_PRIME_FIELD_NAME, None)
    generator = task.get(DH_GENERATOR_FIELD_NAME, None)

    if (not prime) or (not generator):
        raise InternalServerError(description="[Code: 5ee8] Diffie-Hellman parameters are missing.")

    pem = create_pem(prime, generator)
    r = Response(response=pem, status=200, mimetype="text/plain")
    r.headers["Content-Type"] = "text/plain; charset=utf-8"
    return r

@dh_blueprint.route("/dh/<task_id>/exchange/<secret>", strict_slashes=False, methods=["GET"])
def exchange(task_id, secret):
    task_id = str(task_id).strip()
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: 5902] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    prime = task.get(DH_PRIME_FIELD_NAME, None)
    generator = task.get(DH_GENERATOR_FIELD_NAME, None)
    text = task.get(TEXT_FIELD_NAME, None)

    prime = Hex.filter(prime)
    generator = Hex.filter(generator)

    if (not prime) or (not generator):
        raise InternalServerError(description="[Code: 5ee8] Diffie-Hellman parameters are missing.")

    if not secret:
        raise BadRequest(description="[Code: 500c] Secret is expected.")

    if len(secret) > MAX_SECRET_LENGTH:
        raise RequestEntityTooLarge(description="[Code: 500c] Secret is too long.")

    try:
        prime = int(prime, 16)
        generator = int(generator, 16)
        secret = int(Hex.filter( secret.strip()), 16)
    except:
        raise BadRequest(description="[Code: 500c] Secret must be a valid HEX number.")

    b = random.randint(1, prime - 1)

    sB = hex(pow(generator, b, prime))[2:].zfill(MAX_SECRET_LENGTH)

    keys = hex(pow(secret, b, prime))[2:].zfill(MAX_SECRET_LENGTH)
    iv = keys[:32]
    key = keys[32:]

    print("")
    print("Keys: %s" % keys)
    print("IV: %s" % iv)
    print("Key: %s" % key)
    print("Text: %s" % text)
    print("")

    try:

        padder = padding.PKCS7(BLOCK_SIZE_IN_BITS).padder()
        padded_data = padder.update(text.encode("ascii"))
        padded_data += padder.finalize()

        algorithm = algorithms.AES(key=bytearray.fromhex(key))
        cipher = Cipher(algorithm, mode=modes.CBC(bytearray.fromhex(iv)))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        ciphertext = binascii.hexlify(ciphertext).decode("utf-8")
    except Exception as e:
        raise InternalServerError(description="[Code: 58f1] Error happened while encrypting the text: %s" % str(e))

    output = {
        "sB": str(int(sB, 16)),
        "keys": keys,
        "iv": iv,
        "key": key,
        "a": str(b),
        "_prime": str(prime),
        "generator": str(generator),
        "b": secret,
        "ciphertext": ciphertext
    }

    output = {"sB": sB, "ciphertext": ciphertext}

    return jsonify(output)

    #r = Response(response=ga, status=200, mimetype="text/plain")
    #r.headers["Content-Type"] = "text/plain; charset=utf-8"
    #return r

