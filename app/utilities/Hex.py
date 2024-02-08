import string
import random

class Hex:

    HEXS = "0123456789abcdef"

    @staticmethod
    def filter(hexs, extra_symbols=[]):
        return "".join( filter(lambda c: (c in string.hexdigits) or (c in extra_symbols), hexs) )

    @staticmethod
    def string2hex(s):
        return "".join([hex(ord(c)).replace("0x", "") for c in s])

    @staticmethod
    def int2hex(n):
        return hex(n)[2:]

    @staticmethod
    def hex2string(hexs):
        if len(hexs) & 0x01:
            raise Exception("Provided HEX number consisted of odd number of chars.")
        try:
            hexs = [hexs[2 * i:2 * (i + 1)] for i in range(int(len(hexs) / 2))]
            s = "".join([chr(int(h, 16)) for h in hexs])
        except Exception as e:
            raise e
        return s

    @staticmethod
    def hex2bin(hexs, sep=""):
        binaries = [bin(int(c, 16))[2:].zfill(4) for c in hexs]
        return sep.join(binaries)

    @staticmethod
    def bin2hex(binaries, sep=""):
        if len(binaries) % 4 > 0:
            raise Exception("Hex.bin2hex() requires a binary word of size, which is a multiple of 4")
        hexs = [ hex(int(binaries[4*i: 4*(i+1)], 2))[2:] for i in range(int(len(binaries) / 4))]
        return sep.join(hexs)

    @staticmethod
    def random_hex(n=12):
        return "".join(random.choices(Hex.HEXS, k=n))