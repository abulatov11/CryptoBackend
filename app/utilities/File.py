import os
import json

class File:

    @staticmethod
    def read(filename, supress_exception=False):
        if not os.path.exists(filename):
            if not supress_exception:
                raise FileExistsError("File '%s' does not exist." % filename)
            return ""
        data = ""
        with open(filename, "r") as file_idx:
            data = file_idx.read()
        return data.strip()

    @staticmethod
    def read_json(filename, supress_exception=False):
        data = File.read(filename, supress_exception=supress_exception)
        if not data:
            return None
        try:
            data = json.loads(data)
        except Exception as e:
            data = None
            if not supress_exception:
                raise e
        return data