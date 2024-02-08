from flask import Blueprint
from flask import request, jsonify, current_app
from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound
from app.utilities.OpenSSL import OpenSSL
from app.utilities.File import File
from app.utilities.Hex import Hex
import json
import string
import os
import random
import hashlib

assignment3 = Blueprint("assignment3", __name__)
DATA_FILE = os.path.join("app", "data", "assignment 3", "padding-oracle-attack.json")

@assignment3.route("/command/<task_id>/<iv>/<ciphertext>", strict_slashes=False)
def command(task_id, iv, ciphertext):
    
    iv = Hex.filter( iv.lower() )
    ciphertext = Hex.filter( ciphertext.lower() )
    
    tasks = File.read_json(DATA_FILE, supress_exception=True)
    
    if not tasks:
        raise InternalServerError(description="Corrupted list of API keys. Couldn't proceed.")

    if task_id not in tasks:
        raise NotFound()

    if not ciphertext:
        raise InternalServerError("Command is expected.")

    if len(ciphertext) % 32 > 0:
        raise InternalServerError("Ciphertext is expected to have a multiple of 32 HEX symbols; %d HEXs were submitted instead" % len(ciphertext))

    if not iv:
        raise InternalServerError("IV is expected.")

    if len(iv) != 32:
        raise InternalServerError("IV is expected to have 32 HEX symbols; %d HEXs were submitted instead." % len(iv))
    

    try:  

        task = tasks[task_id]
        key = task["key"]
        #iv = task["iv"]
        plaintext = task["plaintext"].strip()

        openssl = OpenSSL(iv=iv, key=key, ciphertext=ciphertext, cipher=OpenSSL.AES128_CBC)
        decoded_text = openssl.decrypt()

        #print("DECODED: " + decoded_text)

        if decoded_text.strip() == plaintext:
            return "Command accepted"
        else:
            return "Unknown command, process, and/or arguments"
    
    except KeyError:
        raise InternalServerError(description="Corrupted local list of keys.")

    except ChildProcessError:
        raise InternalServerError()
