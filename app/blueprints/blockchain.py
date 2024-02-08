from flask import Blueprint
from app.utilities.File import File
from flask import jsonify
import re
import random
from app.utilities.Hex import Hex
import time
import hashlib
import binascii

from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound
import os

blockchain_blueprint = Blueprint("blockchain", __name__)

# constants needed for the blueprint
DATA_FILE = os.path.join("app", "data", "blockchain.json")

OLDEST_TIMESTAMP_DELTA_IN_SECONDS = 100

PREVIOUS_BLOCK_HASH_KEY = "previous-block-hash"
SUCCESS_TOKEN_KEY = "success-token"

TARGET_FROM_HASH_LENGTH = 4
BLOCK_HEADER_LENGTH_IN_HEXS = 80 * 2

VERSION_POSITION = 0
VERSION_LENGTH_IN_HEXS = 8

PREVIOUS_BLOCK_HASH_POSITION = VERSION_POSITION + VERSION_LENGTH_IN_HEXS
PREVIOUS_BLOCK_HASH_LENGTH_IN_HEXS = 64

MERKLE_ROOT_POSITION = PREVIOUS_BLOCK_HASH_POSITION + PREVIOUS_BLOCK_HASH_LENGTH_IN_HEXS
MERKLE_ROOT_LENGTH_IN_HEXS = 64

TIMESTAMP_POSITION = MERKLE_ROOT_POSITION + MERKLE_ROOT_LENGTH_IN_HEXS
TIMESTAMP_LENGTH_IN_HEXS = 8

TARGET_POSITION = TIMESTAMP_POSITION + TIMESTAMP_LENGTH_IN_HEXS
TARGET_LENGTH_IN_HEXS = 8

NONCE_POSITION = TARGET_POSITION + TARGET_LENGTH_IN_HEXS
NONCE_LENGTH_IN_HEXS = 8

def switch_endianness(hexs):
    if len(hexs) & 0x01:
        return None
    bytes = [hexs[2*i:2*(i+1)] for i in range(int(len(hexs)/2))]
    #print(bytes)
    return "".join(bytes[::-1])



def guess_target(previous_block_hash):
    position = re.search("[1-9a-fA-F]", previous_block_hash)
    if not position:
        return None

    position = int(position.start())
    target = previous_block_hash[position:position + TARGET_FROM_HASH_LENGTH]
    target = (int(target, 16) + random.randint(1, 16**3)) & 0xFFFFFF
    target = hex(target).replace("0x", "")

    right_zeros = 64 - position - len(target)
    right_zeros = right_zeros - (right_zeros & 0x01)

    index = int(4 * right_zeros / 8) + 3

    target += ("0" * (64 - position - len(target) - right_zeros))
    target = ("0" * (6 - len(target))) + target

    return hex(index).replace("0x", "") + target

def target_to_hash_repr(target):
    if len(target) != 8:
        raise Exception("Broken target.")

    hash = target[2:8] + ("0" * (2 * (int(target[0:2], 16) - 3)))
    hash = ("0" * (64 - len(hash))) + hash

    return hash

def parse_block_header(block_header):

    block_header = Hex.filter(block_header)

    if len(block_header) != BLOCK_HEADER_LENGTH_IN_HEXS:
        raise Exception("Block header must be 80 bytes long HEX encoded number.")

    version = switch_endianness(block_header[VERSION_POSITION: PREVIOUS_BLOCK_HASH_POSITION])
    previous_block_hash = switch_endianness(block_header[PREVIOUS_BLOCK_HASH_POSITION: MERKLE_ROOT_POSITION])
    merkle_root = switch_endianness(block_header[MERKLE_ROOT_POSITION: TIMESTAMP_POSITION])
    timestamp = switch_endianness(block_header[TIMESTAMP_POSITION: TARGET_POSITION])
    target = switch_endianness(block_header[TARGET_POSITION: NONCE_POSITION])
    nonce = switch_endianness(block_header[NONCE_POSITION: BLOCK_HEADER_LENGTH_IN_HEXS])

    if len(version) != VERSION_LENGTH_IN_HEXS:
        raise Exception("Version must be a 4 bytes long HEX number.")
    if len(previous_block_hash) != PREVIOUS_BLOCK_HASH_LENGTH_IN_HEXS:
        raise Exception("Previous block hash must be a 32 bytes long HEX number.")
    if len(merkle_root) != MERKLE_ROOT_LENGTH_IN_HEXS:
        raise Exception("Merkle root must be a 32 bytes long HEX number.")
    if len(timestamp) != TIMESTAMP_LENGTH_IN_HEXS:
        raise Exception("Timestamp must be a 4 bytes long HEX number.")
    if len(target) != TARGET_LENGTH_IN_HEXS:
        raise Exception("Target must be a 4 bytes long HEX number.")
    if len(nonce) != NONCE_LENGTH_IN_HEXS:
        raise Exception("Nonce must be a 4 bytes long HEX number.")

    components = {
        "version": {
            "hex": version,
            "int": int(version, 16)
        },
        "previous_block_hash": {
            "hex": previous_block_hash,
            "int": int(previous_block_hash, 16)
        },
        "merkle_root": {
            "hex": merkle_root,
            "int": int(merkle_root, 16)
        },
        "timestamp": {
            "hex": timestamp,
            "int": int(timestamp, 16)
        },
        "target": {
            "hex": target,
            "int": int(target, 16)
        },
        "nonce": {
            "hex": nonce,
            "int": int(nonce, 16)
        }
    }
    print(components)
    return components


def validate_header(header, previous_block_hash):
    target = guess_target(previous_block_hash)

    if header.get("previous_block_hash", {"int": 0}).get("int", 0) != int(previous_block_hash, 16):
        raise Exception("Submitted previous block hash is not equal to the hash of the last block.")
    if header.get("version", {"int": 100}).get("int", 100) > 2:
        raise Exception("Not supported version number.")
    if abs(header.get("timestamp", {"int": 0}).get("int", 0) - time.time()) > OLDEST_TIMESTAMP_DELTA_IN_SECONDS:
        raise Exception("Timestamp of your block seems to be a little off.")
    if header.get("target", {"int": -12}).get("int", -12) != int(target, 16):
        raise Exception("Wrong target.")

    return True


def check_block_hash_vs_target(header):
    hex =  switch_endianness(header.get("version", {"hex": ""}).get("hex", ""))
    hex += switch_endianness(header.get("previous_block_hash", {"hex": ""}).get("hex", ""))
    hex += switch_endianness(header.get("merkle_root", {"hex": ""}).get("hex", ""))
    hex += switch_endianness(header.get("timestamp", {"hex": ""}).get("hex", ""))
    hex += switch_endianness(header.get("target", {"hex": ""}).get("hex", ""))
    hex += switch_endianness(header.get("nonce", {"hex": ""}).get("hex", ""))
    hex = binascii.unhexlify(hex)
    block_hash = switch_endianness(hashlib.sha256( hashlib.sha256(hex).digest() ).hexdigest())

    target_hash = target_to_hash_repr(header.get("target", {"hex": ""}).get("hex", ""))
    #print("TARGET: " + target_hash)

    #print("BLOCK:  " + block_hash)
    return int(target_hash, 16) >= int(block_hash, 16)


@blockchain_blueprint.route("/blockchain/lastblock/<task_id>/", strict_slashes=False, methods=["GET"])
def lastblock(task_id):

    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: df40] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    random.seed(task_id)

    previous_block_hash = tasks[task_id].get(PREVIOUS_BLOCK_HASH_KEY, None)
    if (not previous_block_hash):
        raise InternalServerError(description="[Code: df41] Corrupted list of API keys. Couldn't proceed.")

    try:
        target = guess_target(previous_block_hash)
    except Exception as e:
        raise InternalServerError(description="[Code: a77b] Invalid target.")

    if (not target):
        raise InternalServerError(description="[Code: df42] Corrupted list of API keys. Couldn't proceed.")

    return jsonify({
        "previous-block-hash": previous_block_hash,
        "target": target
    })


@blockchain_blueprint.route("/blockchain/submit/<task_id>/<block_header>", strict_slashes=False, methods=["GET"])
def submit(task_id, block_header):
    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: ea10] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    random.seed(task_id)

    previous_block_hash = tasks[task_id].get(PREVIOUS_BLOCK_HASH_KEY, None)
    success_token = tasks[task_id].get(SUCCESS_TOKEN_KEY, None)

    if (not previous_block_hash) or (not success_token):
        raise InternalServerError(description="[Code: df45] Corrupted list of API keys. Couldn't proceed.")

    try:
        parsed_header = parse_block_header(block_header)
        validate_header(parsed_header, previous_block_hash)
        if check_block_hash_vs_target(parsed_header):
            result = {
                "status": "accepted",
                "token": success_token
            }
        else:
            result = {
                "status": "rejected",
                "reason": "Submitted block header exceeds target."
            }
    except Exception as e:
        raise BadRequest(description="[Code: 1aed] %s" % str(e))

    return jsonify(result)
