# Created by: Christopher Mclaughlan
# At: University of Aberdeen/Jacobs University Bremen
# Date: 25-05-2020

import getopt, sys, os
from hashlib import blake2b

DEBUG = False
BLOCK_SIZE = 64  # max 64 bytes
SECRET = "1234567812345678123456781234567812345678123456781234567812345678"  # max 64 bytes


def parse_keys(ks):
    return ks.split(" ")


def split(data):
    halfLen = len(data) // 2

    # Split into two blocks
    left = data[0:halfLen]
    right  = data[halfLen:]

    return [left, right]


"""
Encodes string using blake2b()

s = string
k = key

Returns hash
"""

"""
>>> from Crypto.Cipher import AES
>>> from Crypto import Random
>>>
>>> key = b'Sixteen byte key'
>>> iv = Random.new().read(AES.block_size)
>>> cipher = AES.new(key, AES.MODE_CFB, iv)
>>> msg = iv + cipher.encrypt(b'Attack at dawn')
"""
def encode_function(s, k):
    if len(k) > 64:
        print("Error encoding function: key length > 64 bytes")
        exit()

    if len(s) < 1:
        print("Error encoding function: string length < 1 byte")
        exit()

    result = ""  ## String after encoding/decoding

    # Split into BLOCK_SIZE'd blocks
    data = split_blocks(s, BLOCK_SIZE)
    data[-1] = pad_block(data[-1], BLOCK_SIZE, " ")

    # Ensure: 0 < key length < 64 (bytes)
    key = k.encode()
    for block in data:
        # Enure: block length == 64 bytes
        b_data = block.encode()  ## block data in byte format

        b_salt = create_salt(b_data)

        h = blake2b(key=key, salt=b_salt, digest_size=BLOCK_SIZE)
        h.update(b_data)

        result += str(h.digest())  # hexdigest()?

    return result


"""
Create salt using SECRET key and a string.
"""
def create_salt(s):
    if len(s) != 64:
        print("Error creating salt: string != 64 bytes")
        exit()
    if 0 >= len(SECRET) > 64:
        print("Error creating salt: length of SECRET must larger than 0 and "
              "less than 64")
        exit()
    salt = blake2b(key=SECRET.encode(), digest_size=16)
    salt.update(s)
    salt = salt.digest()
    return salt


"""
Splits string into blocks of size n
"""
def split_blocks(s, n):
    return [s[i: i + n] for i in range(0, len(s), n)]


"""
Pads string b with character c to size n
"""
def pad_block(b, n, c):
    last_block_size = len(b)
    if last_block_size != n:
        for i in range(last_block_size + 1, n):
            b += c
    return b



"""
XOR's two strings together.

Returns a string
"""
def xor_string(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


"""
Use of Feistel Cipher algorithm to encode cipher.

Rough algorithm sketch:
    (l || r) = m
    l[i+1] = r[i]
    r[i+1] = l[i] XOR F(r[i], k[i])

data = string to be encoded
keys = list of keys for hash function

Returns cipher string.
"""
def encode(data, keys):
    s = split(data)  ## Split cleartext into two equal size pieces

    for key in keys:
        if DEBUG:
            print(key + "->" + s[0])

        # Ensure: len(f) == len(s[1]); ie. returns the same length string
        f = encode_function(s[1], key)
        # Ensure: s[0] = XOR s[0], f
        s[0] = xor_string(s[0], f)
        s[0], s[1] = s[1], s[0]

    if DEBUG:
        print(s[1] + s[0])

    return s[1] + s[0]


"""
Use of Feistel Cipher algorithm to decode cipher.
Same as encode(), but keys are reversed.

data = hash string to be decoded
keys = list of keys for hash function

Returns decoded cipher as string.
"""
def decode(data, keys):
    s = split(data)  ## Split cipher into two equal size pieces

    keys.reverse()

    for key in keys:
        if DEBUG:
            print(key + "->" + s[0])
        # Ensure: len(f) == len(s[1]); ie. returns the same length string
        f = encode_function(s[1], key)
        # Ensure: s[0] = XOR s[0], f
        s[0] = xor_string(s[0], f)
        s[0], s[1] = s[1], s[0]

    return s[1] + s[0]


"""
Open a file and read the text.
If the length of text inside is odd, append a space to the data, and then 
return the data.
"""
def get_cleartext(f_path):
    file = open(f_path, "r")

    data = file.read().replace('\n', ' ')
    file.close()

    # Temp fix to even string
    if len(data) % 2 != 0:
        data += ' '

    return data


"""
Writes data to a file.
Handles overwriting an existing file.

f_path = path to file to be written to
data = data to be written to file
"""
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
    set_textfile(f_path, data)


"""
Open a file and return the text.
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
    set_textfile(f_path, data)


"""
Open a file and return the text.

Returns list of keys
"""
def get_ksrc(kPath):
    file = open(kPath, "r")
    keys = file.read().splitlines()
    file.close()
    return keys


"""
Handles incorrect input and exits program.
"""
def usage_error(reason):
    print(reason)
    usage()
    exit(1)

"""
Displays correct way to use input for program
"""
def usage():
    # print("Usage: feistel-cipher.py -[e|d] <file.txt> -s")
    print("Usage: feistel_cipher.py "
          "--[esrc/dsrc/epath/dpath] "
          "--[ksrc/kpath] "
          "--dst"
          "-h --help")

def help():
    print("HELP PLACEHOLDER")


if __name__ == '__main__':
    eSrc, dSrc, ePath, dPath, kSrc, kPath, dst = '', '', '', '', '', '', ''
    opts = []

    # Parse arguments
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "h",
            ["help", "esrc=", "dsrc=", "epath=", "dpath=", "ksrc=", "kpath=", "dst="]
        )
    except getopt.GetoptError as err:
        print(err)
        exit(1)

    for o, a in opts:
        if o in ("-h", "--help"):
            help()
            exit()
        elif o == "--esrc":
            eSrc = a
        elif o == "--dsrc":
            dSrc = a
        elif o == "--epath":
            ePath = a
        elif o == "--dpath":
            dPath = a
        elif o == "--ksrc":
            kSrc = a
        elif o == "--kpath":
            kPath = a
        elif o == "--dst":
            dst = a
        else:
            usage_error("Argument not recognised")

    # Handle wrong arguments
    if (eSrc and dSrc) or (ePath and dPath):
        usage_error("Cannot encode and decode at the same time.")
    if (eSrc and ePath) or (dSrc and dPath):
        usage_error("Cannot provide source and path.")
    if kSrc and kPath:
        usage_error("Cannot provide key source and key path.")
    if not (eSrc or ePath or dSrc or dPath):
        usage_error("No encoding or decoding provided.")

    # Get keys
    keys = ''
    if kPath:
        keys = get_ksrc(kPath)
    elif kSrc:
        keys = parse_keys(kSrc)
    else:
        usage_error("No keys provided.")

    # Encode cipher
    if ePath:
        if ePath[-4:] != ".txt":
            usage_error(f'file: {ePath} must be a .txt file')
        eSrc = get_cleartext(ePath)

    if eSrc:
        cipher = encode(eSrc, keys)
        print(cipher)
        if dst:
            set_ciphertext(dst, cipher)
            exit()

    if dPath:
        if dPath[-4:] != ".txt":
            usage_error(f'file: {dPath} must be a .txt file')
        dSrc = get_ciphertext(dPath)

    if dSrc:
        cleartext = decode(dSrc, keys)
        print(cleartext)
        if dst:
            set_cleartext(dst, cleartext)
            exit()

    exit()
