from flask import Blueprint
from flask import send_file
from werkzeug.exceptions import MethodNotAllowed, RequestEntityTooLarge, BadRequest, InternalServerError, NotFound
import os

files = Blueprint("files", __name__)

FILES = {
    "13665996": {"path": os.path.join("app", "static", "test.py"), "mimetype": "text/x-python"}
}

@files.route("/files/<file_id>", strict_slashes=True, methods=["GET"])
def download_file(file_id):
    try:
        if (file_id not in FILES) or (not os.path.exists(FILES[file_id].get("path"))):
            raise NotFound()
        file_idx = open(FILES[file_id].get("path"), "rb")
        return send_file(
            file_idx, 
            mimetype=FILES[file_id].get("mimetype", None), 
            as_attachment=True, 
            attachment_filename=FILES[file_id].get("filename", os.path.basename(FILES[file_id].get("path")))
        )
    except Exception as e:
        raise InternalServerError(description=str(e))