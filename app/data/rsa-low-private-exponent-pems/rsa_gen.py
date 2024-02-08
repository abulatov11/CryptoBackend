import random
import math
import os

def genprime(n, filename="prime.txt"):
    prime = ""
    os.system("openssl prime -generate -bits %d > %s" % (n, filename))
    with open(filename, "r") as file_idx:
        prime = file_idx.read().strip()
    return int(prime)

def modinv(a, m):
    m0 = m
    y = 0
    x = 1
    if (m == 1):
        return 0
    while (a > 1):
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + m0
    return x

def prepare_asn(p, q, e, d):
    coeff = modinv(q, p)
    output = []
    output.append("asn1=SEQUENCE:rsa_key")
    output.append("")
    output.append("[rsa_key]")
    output.append("version=INTEGER:0")
    output.append("modulus=INTEGER:%d" % (p * q))
    output.append("pubExp=INTEGER:%d" % e)
    output.append("privExp=INTEGER:%d" % d)
    output.append("p=INTEGER:%d" % p)
    output.append("q=INTEGER:%d" % q)
    output.append("e1=INTEGER:%d" % (d % (p-1)))
    output.append("e2=INTEGER:%d" % (d % (q-1)))
    output.append("coeff=INTEGER:%d" % coeff)
    return "\n".join(output)

HEXS = "0123456789abcdef"

bits = 1024

p = None
q = None

if not p:
    p = genprime(bits)
if not q:
    q = genprime(bits)

p1 = max(p, q)
q1 = min(p, q)

p = p1
q = q1

phi = (p-1) * (q - 1)
n = p*q

target_length = int(len(hex(n)[2:]) / 4)

e = None
d = None

while True:
    
    t = p // q
    if t > 2:
        print("ERROR: p/q > 2")
        quit()
    d = "".join([HEXS[random.randint(0, 15)] for _ in range(target_length) ])
    d = int(d, 16)
    try:
        e = modinv(d, phi)
    except:
        continue
    if math.gcd(e, phi) > 1:
        continue

    print("p = " + str(p))
    print("")
    print("q = " + str(q))
    print("")
    print("p/q = " + str(t))
    print("")
    print("n = " + str(n))
    print("")
    print("e = " + str(e))
    print("")
    print("d = " + str(d))
    print("")
    print("ed mod phi(n) = " + str(e * d % phi))
    print("")
    print("-" * 80)

    asn_filename = "asn.txt"
    with open(asn_filename, "w") as file_idx:
        file_idx.write(prepare_asn(p, q, e, d))

    print("\n\nSAVED >> %s\n" % asn_filename )

    break

counter = 1
filename = "private.key." + str(counter) + ".pem"
while os.path.exists(filename):
    counter += 1
    filename = "private.key." + str(counter) + ".pem"

os.system("openssl asn1parse -genconf asn.txt -out newkey.der")
os.system("openssl rsa -inform DER -in newkey.der -outform PEM -out " + filename)
os.system("openssl rsa -text -check -in %s -noout" % filename)
