from flask import Blueprint
from flask import jsonify
import psutil
import socket
from app.utilities.Hex import Hex
import datetime
import time

heartbeat_blueprint = Blueprint("heartbeat", __name__)

SERVER_ID = Hex.random_hex(n=5)

@heartbeat_blueprint.route("/heartbeat", strict_slashes=False, methods=["GET"])
def healthcheck():
    try:
        mem = psutil.virtual_memory()
        now = datetime.datetime.now()
        output = {
            "is-alive": 1,
            "host": "",
            "cpu_usage (%)": psutil.cpu_percent(interval=0.1),
            "cpu_count": psutil.cpu_count(),
            "mem_total": mem.total,
            "mem_used": mem.used,
            "mem_available": mem.available,
            "mem_usage (%)": mem.percent,
            "server-id": SERVER_ID,
            "current-time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "unix-epoch": time.time()
        }
    except Exception as e:
        output = {"error": str(e)}
    return jsonify(output)
