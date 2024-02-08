from flask import Blueprint
from flask import jsonify
from app.utilities.File import File
from app.utilities.Hash import MyHash
from app.utilities.Hex import Hex
import os
from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound

authenticate_blueprint = Blueprint("hash", __name__)

DATA_FILE = os.path.join("app", "data", "authenticate.json")

KEY_1_LENGTH = 16
KEY_2_LENGTH = 16
MAC_TAG_LENGTH = 32

def hex2bin(hexs, digits=128):
    return bin(int(hexs, 16))[2:].zfill(digits)

def parse_message(message):
    components = None
    try:
        mac_tag = message[-MAC_TAG_LENGTH:]
        key2 = message[-(KEY_2_LENGTH + MAC_TAG_LENGTH) : -MAC_TAG_LENGTH]
        key1 = message[-(KEY_1_LENGTH + KEY_2_LENGTH + MAC_TAG_LENGTH): -(KEY_2_LENGTH + MAC_TAG_LENGTH)]
        data = message[:-(KEY_1_LENGTH + KEY_2_LENGTH + MAC_TAG_LENGTH)]
        components = {
            "mac": mac_tag,
            "key1": key1,
            "key2": key2,
            "data": data
        }
    except Exception as e:
        pass
    return components

def authenticate_message(message):
    components = parse_message(message)
    data = components["data"]
    key1 = components["key1"]
    key2 = components["key2"]
    mac = components["mac"]
    return MyHash.hash(MyHash.hash(data, key1), key2).lower() == mac.lower()

def create_authenticated_message(s):
    hexs = Hex.string2hex(s)
    key1 = Hex.random_hex(KEY_1_LENGTH)
    key2 = Hex.random_hex(KEY_2_LENGTH)
    digest = MyHash.hash(MyHash.hash(hexs, key=key1), key=key2)
    #print("Message: %s" % s)
    #print("HEXs:    %s" % hexs)
    #print("Key1:    %s" % key1)
    #print("Key2:    %s" % key2)
    #print("Digest:  %s" % digest)


def hash_message(s):
    hexs = Hex.string2hex(s)
    key = Hex.random_hex(8)
    digest = MyHash.hash(hexs, key=key)
    #print("Message: %s" % s)
    #print("HEXs:    %s" % hexs)
    #print("Key:     %s" % key)
    #print("Digest:  %s" % digest)

@authenticate_blueprint.route("/authenticate/<task_id>/<data>", strict_slashes=False, methods=["GET"])
def index(task_id, data):

    #test = "48656C6C6F2043727970746F4C6162"
    #key = "b9827426"
    #MyHash.hash(test, key)

    #text = "7b22737461747573223a20226f6b222c2022746f6b656e223a20223138316633653165373665636434336463376631306138363031373733376666222c2022616374696f6e223a20226c6f67696e227d"
    #k1 = "58dcfa0c60ef5b33"
    #k2 = "53ecd34250a4eed1"
    #hash1 = MyHash.hash(text, k1)
    #hash2 = MyHash.hash(hash1, k2)
    #return jsonify({"text-hex": text, "text-ascii": str(bytearray.fromhex(text).decode()), "k1": k1, "k2": k2, "hash1": hash1, "hash2": hash2, "tag": "9e34f004d5d7036f0f711dcdd7cf0a63" })

    task_id = str(task_id)
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    data = Hex.filter(data)

    if not tasks:
        raise InternalServerError(description="[Code: 4ee8] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    task = tasks.get(task_id, {})
    message = task.get("data", None)
    key1 = task.get("key1", None)
    key2 = task.get("key2", None)
    token = task.get("token", None)


    if (not key1) or (not key2):
        raise InternalServerError(description="[Code: 4655] Corrupted list of API keys. Couldn't proceed.")

    if not token:
        raise InternalServerError(description="[Code: 4655] Corrupted list of API keys. Couldn't proceed.")

    if len(data) <= (KEY_1_LENGTH + KEY_2_LENGTH + MAC_TAG_LENGTH):
        min_size = (KEY_1_LENGTH + KEY_2_LENGTH + MAC_TAG_LENGTH) + 1
        raise InternalServerError(description="[Code: 4f19] Your message must consist of at least %d HEX digits" % min_size)

    message_hex = Hex.string2hex(message)
    hash1 = MyHash.hash(message_hex, key1)
    hash2 = MyHash.hash(hash1, key2)

    correct_tagged_message = message_hex + key1 + key2 + hash2

    if data.lower() == correct_tagged_message.lower():
        response = {"status": "ok", "token": token}
    else:
        response = {
            "status": "error",
            "error": "Authentication failed.",
            #"correct": correct_tagged_message.lower(),
            #"message": message,
            #"message_hex": message_hex,
            #"hash1": hash1.lower(),
            #"hash2": hash2.lower(),
            #"key1": key1.lower(),
            #"key2": key2.lower()
        }

    return jsonify(response)