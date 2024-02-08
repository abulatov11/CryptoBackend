import werkzeug
import random


class MyExceptions:

    HEXs = "0123456789abcdef"
    ID_LENGTH = 12

    def __init__(self, description=None, location=None, data=None):
        self.description = description
        self.location = location
        self.data = data
        self.id = "".join(random.choices(MyExceptions.HEXs, k=MyExceptions.ID_LENGTH))

    def werkzeug_exception(self):
        return werkzeug.exceptions.InternalServerError()


class InternalServerError(MyExceptions):

    def __init__(self,description=None, location=None, data=None):
        MyExceptions.__init__(self, description=description, location=location, data=data)

    def werkzeug_exception(self):
        return werkzeug.exceptions.InternalServerError(description=self.description)

class NotFound(MyExceptions):

    def __init__(self,description=None, location=None, data=None):
        MyExceptions.__init__(self, description=description, location=location, data=data)

    def werkzeug_exception(self):
        return werkzeug.exceptions.NotFound(description=self.description)