import sys

KEY = "hemankungfoochopsforfourtyninedamageslice"

def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        output_str += chr(ord(current) ^ ord(current_key))

    return output_str

def printCipher(cipher):
    print("{ 0x" + ", 0x".join(hex(ord(x))[2:] for x in cipher) + " };")


try:
    plain = open(sys.argv[1], "rb").read()
except:
    print("File argument needed: %s <raw payload file>" % sys.argv[0])
    sys.exit()


cipher = xor(plain, KEY)

printCipher(cipher)