from flask import Response

class PlainTextResponse(Response):

    def __init__(self, response=None, code=200, mimetype="text/plain"):
        Response.__init__(self, response=str(response), status=code, mimetype=mimetype)
        self.headers["Content-Type"] = "text/plain; charset=utf-8"

