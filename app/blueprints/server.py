from flask import Blueprint
from flask import jsonify
from werkzeug.exceptions import InternalServerError, NotFound, BadRequest
from app.utilities.File import File
from app.utilities.Hex import Hex
from app.utilities.Hash import MyHash
import os
import random
import json

# constants needed for the blueprint
DATA_FILE = os.path.join("app", "data", "server.json")
RANDOM_SEEDS_FILE = os.path.join("app", "data", "server.seeds.json")

MESSAGE_ID_CHARS_NUMBER = 4

LARGEST_MESSAGE_SIZE = 512
RANDOM_SEEDS_LENGTH = 10

MAC_TAG_LENGTH = 32
KEY_1_LENGTH = 16
KEY_2_LENGTH = 16
SHORTEST_MESSAGE_SIZE = MAC_TAG_LENGTH + KEY_1_LENGTH + KEY_2_LENGTH

HEXS = "0123456789abcdef"
GARBAGE_TEXT = "9n8v53364v8934vn98rwcu"

USER_TOKEN_PART_1_LENGTH = 16
USER_TOKEN_PART_2_LENGTH = 16

USER_TOKEN_PART_1_CHECKSUM = 1
USER_TOKEN_PART_2_CHECKSUM = 2

# blueprint definition
server_blueprint = Blueprint("server", __name__)


def create_random_seed():
    return os.urandom(12).hex()


def create_key(key_length, random_seed=None):
    if not random_seed:
        random_seed = create_random_seed()
    #random.seed(random_seed)
    #random.seed(12345670987654321)
    random.seed(key_length)
    key = "".join(random.choices(HEXS, k=key_length))
    print("")
    print("KEY: " + key)
    print("")
    return key


def create_seeds_file(num_seeds=500):
    seeds = ["".join(random.choices(HEXS, k=RANDOM_SEEDS_LENGTH)) for _ in range(num_seeds)]
    with open(RANDOM_SEEDS_FILE, "w") as file_idx:
        file_idx.write(json.dumps(seeds, indent=4))


def read_seeds_file():
    if not os.path.exists(RANDOM_SEEDS_FILE):
        create_seeds_file()
    if not os.path.exists(RANDOM_SEEDS_FILE):
        raise InternalServerError(description="[Code: 331b] Could not initialize random seed.")
    with open(RANDOM_SEEDS_FILE, "r") as file_idx:
        seeds_list = file_idx.read()
    try:
        seeds = json.loads(seeds_list)
    except Exception as e:
        raise InternalServerError(description="[Code: 3fa6] Could not initialize random seed.")
    return seeds


def xor(a, b):
    c = int(a, 16) ^ int(b, 16)
    c = hex(c)[2:]
    return ("0" * (len(a) - len(c))) + c


def error(message):
    return {"status": "error", "error": message}


def parse_message(message):

    print("MESSAGE: " + message)

    components = None
    try:
        mac_tag = message[-MAC_TAG_LENGTH:]
        key2 = message[-(KEY_2_LENGTH + MAC_TAG_LENGTH) : -MAC_TAG_LENGTH]
        key1 = message[-(KEY_1_LENGTH + KEY_2_LENGTH + MAC_TAG_LENGTH): -(KEY_2_LENGTH + MAC_TAG_LENGTH)]
        data = message[:-SHORTEST_MESSAGE_SIZE]
        js = json.loads( Hex.hex2string(data))
        components = {
            "mac": mac_tag,
            "key1": key1,
            "key2": key2,
            "json": js,
            "data_hex": data
        }

        print(components)

    except Exception as e:

        print("DATA:    " + data)
        print("ERROR(json): " + str(e))

        pass
    return components


def authenticate(message, key1, key2, mac):
    message_hash = MyHash.hash(MyHash.hash(message, key=key1), key=key2)
    return mac.lower() == message_hash.lower()


def create_user_token():
    half1 = random.choices(range(16), k=max(USER_TOKEN_PART_1_LENGTH - 1, 0))
    checksum1 = sum(half1) % 16
    half1.append( (16 - (checksum1 - USER_TOKEN_PART_1_CHECKSUM)) % 16 )

    half2 = random.choices(range(16), k=max(USER_TOKEN_PART_2_LENGTH - 1, 0))
    checksum2 = sum(half2) % 16
    half2.append((16 - (checksum2 - USER_TOKEN_PART_2_CHECKSUM)) % 16)

    half1_hex = "".join([hex(x).replace("0x", "") for x in half1])
    half2_hex = "".join([hex(x).replace("0x", "") for x in half2])

    return half1_hex + half2_hex


def check_user_token(token):

    print("Token: " + token)

    if len(token) != (USER_TOKEN_PART_1_LENGTH + USER_TOKEN_PART_2_LENGTH):
        return False

    half1 = [int(c, 16) for c in token[0:USER_TOKEN_PART_1_LENGTH]]
    half2 = [int(c, 16) for c in token[USER_TOKEN_PART_1_LENGTH:]]

    checksum1 = sum(half1) % 16
    checksum2 = sum(half2) % 16

    print("Half1: " + str(checksum1))
    print(half1)
    print("Half2: " + str(checksum2))
    print(half2)

    return (checksum1 == USER_TOKEN_PART_1_CHECKSUM) and (checksum2 == USER_TOKEN_PART_2_CHECKSUM)


def login(data):
    if "user" not in data:
        raise Exception("Missing 'user' field")
    if "password" not in data:
        raise Exception("Missing 'password' field")

    user = data["user"]
    password = data["password"]

    system_user = data.get("system", {}).get("user", GARBAGE_TEXT)
    system_password = data.get("system", {}).get("password", GARBAGE_TEXT)

    if (user != system_user) or (password != system_password):
        raise Exception("There are no users in the system with provided user/password pair")

    return {"status": "ok", "token": create_user_token(), "action": "login"}


def get_variable(data):
    if ("variable" not in data) or (not data.get("variable", None)):
        raise Exception("Missing 'variable' field")
    variable = data.get("variable").strip()
    value = data.get("system", {}).get("variables", {}).get(variable, None)
    if not value:
        raise Exception("There is no variable '%s' in the system" % variable)
    return {"status": "ok", "action": "get-variable", "token": create_user_token(), variable: value}


def handle_request(data):
    try:
        if not "action" in data:
            raise Exception("Missing 'action' field")

        action = data["action"].strip()

        if action == "login":
            return login(data)

        if "token" not in data:
            raise Exception("Missing 'token' field")

        token = data.get("token", "")
        if not check_user_token(token):
            raise Exception("Invalid user token")

        if action == "get-variable":
            return get_variable(data)

    except Exception as e:
        return error(str(e))


def prepare_and_sign_json(data, mac=None):
    message = Hex.string2hex(json.dumps(data))
    key1 = "".join(random.choices(HEXS, k=KEY_1_LENGTH))
    key2 = "".join(random.choices(HEXS, k=KEY_2_LENGTH))
    message_hash = MyHash.hash(MyHash.hash(message, key=key1), key=key2) if not mac else mac
    return message + key1 + key2 + message_hash

def encrypt_json(data, seed=None, mac=None, is_plaintext=False):
    if is_plaintext:
        return jsonify(data)
    message = prepare_and_sign_json(data, mac=mac)
    seed = seed if seed else create_random_seed()
    key = create_key(len(message), random_seed=seed)
    return xor(message, key)


@server_blueprint.route("/server/<task_id>/<message>", strict_slashes=False, methods=["GET"])
def server(task_id, message):

    #create_seeds_file(num_seeds=1000)
    seeds = read_seeds_file()

    task_id = str(task_id)
    message_tmp = Hex.filter(message).lower()
    tasks = File.read_json(DATA_FILE, supress_exception=True)

    if not tasks:
        raise InternalServerError(description="[Code: 3fdb] Corrupted list of API keys. Couldn't proceed.")

    if (not task_id) or (task_id not in tasks):
        raise NotFound()

    if len(message_tmp) <= SHORTEST_MESSAGE_SIZE:
        response = error("Message must contain at least 65 HEXs")
        print("Server => %s" % str(response))
        return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)

    if len(message_tmp) > LARGEST_MESSAGE_SIZE:
        response = error("Message is too large")
        print("Server => %s" % str(response))
        return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)

    if len(message_tmp) != len(message):
        response = error("Non-HEX symbols are not permitted")
        print("Server => %s" % str(response))
        return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)

    if parse_message(message_tmp):

        d = parse_message(message_tmp)
        print(d)

        print("")
        print("HASH: " + MyHash.hash(MyHash.hash(d["data_hex"], key=d["key1"]), key=d["key1"]) )
        print("TAG:  " + d["mac"])
        print("Action: " + d["json"].get("action", "None"))
        print("")
        response = error("Do not send unencrypted messages")
        print("Server => %s" % str(response))
        return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)

    message = message_tmp
    task = tasks.get(task_id, {})
    seeds = [1]
    #random.seed(len(message))
    for seed in seeds:
        key = create_key(len(message), random_seed=seed)
        plaintext = xor(message, key)
        components = parse_message(plaintext)

        if not components:
            continue

        data_hex = components["data_hex"]
        data = components["json"]
        key1 = components["key1"]
        key2 = components["key2"]
        mac = components["mac"]

        #print("Data:    %s" % data)
        #print("Key1:    %s" % key1)
        #print("Key2:    %s" % key2)
        #print("MAC:     %s" % mac)

        #if not authenticate(data_hex, key1, key2, mac):
        #    response = error("Data seem to be corrupted")
        #    print("Server => %s" % str(response))
        #    return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)

        data["system"] = task

        try:
            response = handle_request(data)
            mac = None

            #if data.get("action", "") != "login":
            #    adversary_probability = task.get("adversary", 0)
            #    if random.random() > adversary_probability:
            #        mac = None
            #    else:
            #        mac = Hex.random_hex(n=MAC_TAG_LENGTH)
            print("Server => %s" % str(response))
            return encrypt_json(response, seed=random.choice(seeds), mac=mac)

        except Exception as e:
            response = error("Some internal server error")
            print("Server => %s" % str(response))
            return encrypt_json(response, seed=random.choice(seeds), is_plaintext=True)


    seed = random.choice(seeds)
    key = create_key(len(message), random_seed=seed)
    ciphertext = xor(message, key)
    print("Server => %s" % ciphertext)

    return ciphertext




