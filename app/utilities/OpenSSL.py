import string
from app.utilities.RunProcess import RunProcess
import tempfile, os, binascii

class OpenSSL:

    AES128_CBC = 1
    AES128_ECB = 2
    AES128_CTR = 3
    AES128_OFB = 4
    AES128_CFB = 5

    AES192_CBC = 11
    AES192_ECB = 12
    AES192_CTR = 13
    AES192_OFB = 14
    AES192_CFB = 15

    AES256_CBC = 21
    AES256_ECB = 22
    AES256_CTR = 23
    AES256_OFB = 24
    AES256_CFB = 25
    
    def __init__(self, iv=None, key=None, plaintext=None, is_hex_plaintext=False, ciphertext=None, cipher=None, infile=None, outfile=None):
        self.iv = ""
        self.key = ""
        self.plaintext = ""
        self.ciphertext = ""
        self.cipher = None
        self.infile = None
        self.outfile = None

        self.ciphers_mapping = {
            self.AES128_CBC: {"mode": "-aes-128-cbc", "key-size": 16},
            self.AES128_ECB: {"mode": "-aes-128-ecb", "key-size": 16},
            self.AES128_CTR: {"mode": "-aes-128-ctr", "key-size": 16},
            self.AES128_OFB: {"mode": "-aes-128-ofb", "key-size": 16},
            self.AES128_CFB: {"mode": "-aes-128-cfb", "key-size": 16},
            self.AES192_CBC: {"mode": "-aes-192-cbc", "key-size": 24},
            self.AES192_ECB: {"mode": "-aes-192-ecb", "key-size": 24},
            self.AES192_CTR: {"mode": "-aes-192-ctr", "key-size": 24},
            self.AES192_OFB: {"mode": "-aes-192-ofb", "key-size": 24},
            self.AES192_CFB: {"mode": "-aes-192-cfb", "key-size": 24},
            self.AES256_CBC: {"mode": "-aes-256-cbc", "key-size": 32},
            self.AES256_ECB: {"mode": "-aes-256-ecb", "key-size": 32},
            self.AES256_CTR: {"mode": "-aes-256-ctr", "key-size": 32},
            self.AES256_OFB: {"mode": "-aes-256-ofb", "key-size": 32},
            self.AES256_CFB: {"mode": "-aes-256-cfb", "key-size": 32}
        }

        if iv:
            self.set_iv(iv)
        if key:
            self.set_key(key)
        if plaintext:
            self.set_plaintext(plaintext, is_hex_plaintext=is_hex_plaintext)
        if ciphertext:
            self.set_ciphertext(ciphertext)
        if cipher:
            self.set_cipher(cipher)
        if infile:
            self.set_infile(infile)
        if outfile:
            self.set_outfile(outfile)

    def set_iv(self, iv):
        self.iv = self.__sanitize(iv)
        return self

    def set_key(self, key):
        self.key = self.__sanitize(key)
        return self

    def set_plaintext(self, plaintext, is_hex_plaintext=False):
        if is_hex_plaintext:
            plaintext = binascii.unhexlify(self.__sanitize(plaintext))
        self.plaintext = plaintext
        return self

    def set_ciphertext(self, ciphertext):
        self.ciphertext = self.__sanitize(ciphertext)
        return self

    def set_cipher(self, cipher):
        if not cipher in self.ciphers_mapping:
            raise TypeError("Not a valid cipher")
        self.cipher = cipher
        return self

    def set_infile(self, infile):
        self.infile = infile
        return self

    def set_outfile(self, outfile):
        self.outfile = outfile
        return self

    def encrypt(self):
        if not self.iv:
            raise Exception("IV must be assigned before encryption")
        if not self.key:
            raise Exception("Key must be assigned before encryption")
        if (not self.plaintext) and (not self.infile):
            raise Exception("Plaintext or infile must be assigned before encryption")
        if not self.cipher:
            raise Exception("Cipher must be assigned before encryption")
        
        in_file = None
        in_fd = None

        out_file = None
        out_fd = None

        ciphertext = ""
        
        try:
            command = ["openssl", "enc", self.ciphers_mapping[self.cipher]["mode"], "-K", self.key]

            if self.plaintext:
                in_fd, in_file = tempfile.mkstemp()
                with os.fdopen(in_fd, "wb") as tmp_file:
                    tmp_file.write(self.plaintext)
            else:
                in_file = self.infile

            if not self.outfile:
                out_fd, out_file = tempfile.mkstemp()
            else:
                out_file = self.outfile

            command.extend(["-in", in_file, "-out", out_file])

            if self.cipher not in [self.AES128_ECB, self.AES192_ECB, self.AES256_ECB]:
                command.extend(["-iv", self.iv])
            print("COMMAND: %s" % " ".join(command))
            process = RunProcess(command=command, timeout=5)
            ciphertext, error = process.run()

            if os.path.exists(out_file):
                with open(out_file, "rb") as tmp_file:
                    ciphertext = binascii.hexlify(tmp_file.read()).decode("ascii")
                    #print("READ: %s" % ciphertext)
            
            if (error and "hex string is too short" not in error) or (not ciphertext):
                raise ChildProcessError(error)
        
        except Exception as e:
            #print(str(e))
            raise e
        finally:
            if in_fd and os.path.exists(in_file):
                os.remove(in_file)
                del in_fd
            if out_fd and os.path.exists(out_file):
                os.remove(out_file)
                del out_fd
            
        return ciphertext

    def decrypt(self):
        if not self.iv:
            raise ChildProcessError("IV must be assigned before encryption")
        if not self.key:
            raise ChildProcessError("Key must be assigned before encryption")
        if (not self.ciphertext) and (not self.infile):
            raise ChildProcessError("Plaintext or infile must be assigned before encryption")
        if not self.cipher:
            raise ChildProcessError("Cipher must be assigned before encryption")
        if self.infile and not os.path.exists(self.infile):
            raise ChildProcessError("File '%s' does not exist")
        
        in_file = None
        in_fd = None

        out_file = None
        out_fd = None

        plaintext = ""
        
        try:
            command = ["openssl", "enc", "-d", self.ciphers_mapping[self.cipher]["mode"], "-K", self.key]

            if self.ciphertext:
                in_fd, in_file = tempfile.mkstemp()
                with os.fdopen(in_fd, "wb") as tmp_file:
                    tmp_file.write(binascii.unhexlify(self.ciphertext))
            else:
                in_file = self.infile

            if not self.outfile:
                out_fd, out_file = tempfile.mkstemp()
            else:
                out_file = self.outfile

            command.extend(["-in", in_file, "-out", out_file])

            if self.cipher not in [self.AES128_ECB, self.AES192_ECB, self.AES256_ECB]:
                command.extend(["-iv", self.iv])

            process = RunProcess(command=command, timeout=5)
            plaintext, error = process.run()

            if os.path.exists(out_file):
                with open(out_file, "r") as tmp_file:
                    plaintext = tmp_file.read()
            
            if error or (not plaintext):
                raise ChildProcessError(error)
        
        except Exception as e:
            raise e
        finally:
            if in_fd and os.path.exists(in_file):
                os.remove(in_file)
                del in_fd
            if out_fd and os.path.exists(out_file):
                os.remove(out_file)
                del out_fd
            
        return plaintext

    def __sanitize(self, text):
        return "".join(filter(lambda c: c in string.hexdigits, text.strip().lower()))

    def key_size(self, cipher):
        if cipher not in self.ciphers_mapping:
            raise TypeError("Not a valid cipher")
        return self.ciphers_mapping.get(cipher, {}).get("key-size", None)