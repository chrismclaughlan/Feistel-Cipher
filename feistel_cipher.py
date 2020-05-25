# Created by: Christopher Mclaughlan
# At: University of Aberdeen/Jacobs University Bremen
# Date: 25-05-2020

import getopt, sys, os
from hashlib import blake2b

save = False  ## Whether or not result gets saved to .txt


"""
"""
def usage():
    print("Usage: feistel-cipher.py -[e|d] <file.txt> -s")


def parse_keys(ks):
    return ks.split("-")


def split(data):
    halfLen = len(data) // 2

    # Split into two blocks
    left = data[0:halfLen]
    right  = data[halfLen:]

    return [left, right]


"""
s = string
k = key
"""
def encode_function(s, k):
    h = blake2b(key=k.encode(), digest_size=16)
    h.update(s.encode())
    return h.hexdigest()


def xor_string(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


"""
file = file object
keys = list

    (l || r) = m
    l[i+1] = r[i]
    r[i+1] = l[i] XOR F(r[i], k[i])
"""
def encode(data, keys):
    s = split(data)  ## Split cleartext into two equal size pieces

    for key in keys:
        print(key + "->" + s[0])
        s[0] = xor_string(s[0], encode_function(s[1], key))
        s[0], s[1] = s[1], s[0]

    return s[1] + s[0]


"""
file = file object
keys = list

Same as encode() but keys are reversed
"""
def decode(data, keys):
    s = split(data)  ## Split cipher into two equal size pieces

    keys.reverse()

    for key in keys:
        print(key + "->" + s[0])
        s[0] = xor_string(s[0], encode_function(s[1], key))
        s[0], s[1] = s[1], s[0]

    return s[1] + s[0]


"""
Open a file and read the text. If the length of text inside is odd,
append a space to the data, and then return the data.
"""
def get_cleartext(f_path):
    file = open(f_path, "r")

    data = file.read().replace('\n', ' ')
    file.close()

    # Temp fix to even string
    if len(data) % 2 != 0:
        data += ' '

    return data


def set_textfile(f_path, data):

    if os.path.exists(f_path):
        while True:
            res = input(
                f"The file {f_path} already exists, are you sure you would "
                "like to overwrite it? Y/N: ")
            if res in ("y", "Y"):
                break
            elif res in ("n", "N"):
                exit()

    file = open(f_path, "w")
    file.write(data)
    file.close()


"""
Create or open a file and overwrite the contents with clear text.
"""
def set_cleartext(f_path, data):
    f_path = f_path.replace("_cipher.txt", ".txt")  # TODO fix
    set_textfile(f_path, data)


"""
Open a file and read the text. Decode the text and return it.
"""
def get_ciphertext(f_path):
    file = open(f_path, "r")
    data = file.read()
    file.close()

    # Reverse temp fix to even string?

    return data


"""
Create or open a file and overwrite the contents with ciphertext.
"""
def set_ciphertext(f_path, data):
    f_path = f_path.replace(".txt", "_cipher.txt")
    set_textfile(f_path, data)


if __name__ == '__main__':
    fEncode = ''
    fDecode = ''
    fKeys = ''

    # Placeholder values
    fKeys = "qwer-1234-ubfg"

    # Parse arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hse:d:k:", ["help", "save"])
        # opts, args = getopt.getopt(sys.argv[1:], "hedk:",
        #                            ["help", "src", "dst"])
    except getopt.GetoptError as err:
        print(err)
        exit(1)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            exit()
        elif o == "-e":
            fEncode = a
        elif o == "-d":
            fDecode = a
        elif o == "-k":
            fKeys = a
        elif o in ("-s", "--save"):
            save = True

    if fEncode and fDecode:
        print("Cannot encode and decode at the same time")
        usage()
        exit()

    elif fEncode:
        if fEncode[-4:] != ".txt":
            print("File must be a .txt file")
            usage()
            exit()

        d = get_cleartext(fEncode)
        ks = parse_keys(fKeys)
        res = encode(d, ks)
        print (res)
        if save:
            set_ciphertext(fEncode, res)

    elif fDecode:
        if fDecode[-4:] != ".txt":
            print("File must be a .txt file")
            usage()
            exit()

        d = get_ciphertext(fDecode)
        ks = parse_keys(fKeys)
        res = decode(d, ks)
        print(res)
        if save:
            set_cleartext(fDecode, res)

    else:
        usage()

    exit(0)