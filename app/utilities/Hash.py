from app.utilities.Hex import Hex

class MyHash:

    @staticmethod
    def _left_cyclic_rotate(number, shift, size=32):
        shift = shift % size
        template = ((1 << size) - 1)
        number = number & template
        number = (number << shift) | (number >> (size - shift))
        return number & template

    @staticmethod
    def _right_cyclic_rotate(number, shift, size=32):
        template = ((1 << size) - 1)
        shift = shift % size
        number = number & template
        number = (number >> shift) | (number << (size - shift))
        return number & template

    @staticmethod
    def hash(data, key="0123456789"):

        if not key:
            raise Exception("Key must be a string of HEX digits")
        if not data:
            raise Exception("Data must be a string of HEX digits")

        key = int(key, 16)
        data = Hex.filter(data)

        data_bin = Hex.hex2bin(data)
        size_in_bits = len(data_bin)

        #print("")
        #print("ORIGINAL")
        #print("Size: %d" % size_in_bits)
        #for i in range(int(size_in_bits / 128) + 1):
        #    print( data_bin[128*i: 128*(i+1)] )

        data_bin += "1"
        data_bin += "0" * (128 - (size_in_bits + 1 + 64) % 128)
        data_bin += bin(int(size_in_bits))[2:].zfill(64)

        #print("")
        #print("PADDED")
        #print("Padded Size: %d" % len(data_bin))
        #for i in range(int(len(data_bin) / 128) + 1):
        #    block = data_bin[128 * i: 128 * (i + 1)]
        #    print(block)
        #    print(Hex.bin2hex(block))

        data = Hex.bin2hex(data_bin)
        #print("")
        #print("Data HEX:")
        #print(data)
        #print("=" * 80 + "\n")

        #return "0" * 32

        #size_in_bits = 4 * len(data)
        #data += "8" + ("0" * (1 - len(data) & 0x01))
        #size_hex = hex(size_in_bits).replace("0x", "")
        #size_hex = ("0" * (16 - len(size_hex))) + size_hex
        #data = data + ("0" * (32 - (len(data + size_hex) % 32))) + size_hex

        blocks = [data[32 * i: 32 * (i + 1)] for i in range(int(len(data) / 32))]

        a = MyHash._left_cyclic_rotate(0x6148a3b6, key)
        b = MyHash._right_cyclic_rotate(0xa5472a5d, key)
        c = MyHash._left_cyclic_rotate(0x516ed6e1, key)
        d = MyHash._right_cyclic_rotate(0x02246c86, key)

        p = [5, 11, 17, 23, 31]

        for block in blocks:
            b0 = int(block[0: 8], 16)
            b1 = int(block[8: 16], 16)
            b2 = int(block[16: 24], 16)
            b3 = int(block[24: 32], 16)

            #print("Block")
            #print("b0: %d" % b0)
            #print("b1: %d" % b1)
            #print("b2: %d" % b2)
            #print("b3: %d" % b3)
            #print("")
            #print("Before")
            #print("a:  %d" % a)
            #print("b:  %d" % b)
            #print("c:  %d" % c)
            #print("d:  %d" % d)

            for i in range(32):
                at = MyHash._left_cyclic_rotate((d ^ b2), p[b % 5])
                bt = MyHash._right_cyclic_rotate((a ^ b3), p[c % 5])
                ct = MyHash._left_cyclic_rotate((b ^ b0), p[d % 5])
                dt = MyHash._right_cyclic_rotate((c ^ b1), p[a % 5])

                a = ((at + dt)) & 0xffffffff
                b = ((bt + at)) & 0xffffffff
                c = ((ct + bt)) & 0xffffffff
                d = ((dt + ct)) & 0xffffffff

                t = b0
                b0 = b1
                b1 = b2
                b2 = b3
                b3 = t

            #print("")
            #print("After")
            #print("a:  %d" % a)
            #print("b:  %d" % b)
            #print("c:  %d" % c)
            #print("d:  %d" % d)
            #print("-" * 80)
            #print("")

        number = (a << 32) + b
        number = (number << 32) + c
        number = (number << 32) + d

        number = MyHash._left_cyclic_rotate(number, key * number, size=128)

        hex_digest = hex(number).replace("0x", "")
        hex_digest = "0" * (32 - len(hex_digest)) + hex_digest

        return hex_digest