# Created by: Christopher Mclaughlan
# At: University of Aberdeen/Jacobs University Bremen
# Date: 25-05-2020

import getopt, sys, os
from hashlib import blake2b

DEBUG = False
BLOCK_SIZE = 64  # max 64 bytes
SALT_SIZE = 16  # max 16 bytes
SECRET = "1234567812345678123456781234567812345678123456781234567812345678"  # max 64 bytes
PADDING = " "  ## Max. one character. Shouldn't be a common character or full stop
KEY_SPLIT = " "


class EncodeError(Exception):
    def __init__(self, reason, content=None):
        self.reason = reason
        self.content = content
        super().__init__(self.reason)

    def __str__(self):
        if self.content:
            return f"Encoding error: {self.reason} -> {self.content}"
        else:
            return f"Encoding error: {self.reason}"


def parse_keys(ks):
    return ks.split(KEY_SPLIT)


"""
@brief Splits a string into two equal parts.
If length is not equal -> add one padding character to end of second string

@param data, String with length >= 2

@return list, Contains two equal sized strings
"""
def split(data):
    if type(data) != str:
        raise EncodeError("Data must be a string", data)
    elif len(data) < 2:
        raise EncodeError("Cannot split string with length < 2", data)

    halfLen = len(data) // 2

    if len(data) % 2 == 0:
        left = data[0:halfLen]
        right = data[halfLen:]
    else:
        left = data[0:halfLen + 1]
        right = data[halfLen + 1:]
        right += PADDING

    return [left, right]


"""
@brief Encodes string using blake2b()

@param s, "String" String larger than 0
@param k, "Key" String larger than 0 and less than 64

@return Hashed String with the same length as s
"""
def encode_function(s, k):
    if 0 >= len(k) > 64:
        raise EncodeError("Length of key must be between 1 and 64", k)

    if len(s) <= 0:
        raise EncodeError("Length of string must be greater than 0", s)

    result = ""  ## String after encoding/decoding

    # Split into BLOCK_SIZE'd blocks
    data = split_blocks(s, BLOCK_SIZE)
    data[-1] = pad_block(data[-1], BLOCK_SIZE, PADDING)

    # Ensure: 0 < key length < 64 (bytes)
    key = k.encode()
    for block in data:
        # Enure: block length == 64 bytes
        b_data = block.encode()  ## block data in byte format
        b_salt = create_salt(b_data)
        h = blake2b(key=key, salt=b_salt, digest_size=BLOCK_SIZE)
        h.update(b_data)
        result += str(h.digest())

    return result


"""
@brief Create salt using encoded SECRET key and a given bytestring.

@param s, "string" Bytestring with length BLOCK_SIZE

@return Hash string with size SALT_SIZE
"""
def create_salt(s):
    if len(s) != BLOCK_SIZE:
        raise EncodeError(f"String must be exactly {BLOCK_SIZE} bytes", s)
    if 0 >= len(SECRET) > BLOCK_SIZE:
        # CAUTION should SECRET be printed?
        raise EncodeError(f"Length of SECRET must be between 1 and {BLOCK_SIZE}", SECRET)

    salt = blake2b(key=SECRET.encode(), digest_size=SALT_SIZE)
    salt.update(s)
    salt = salt.digest()
    return salt


"""
@brief Splits string into blocks of size n

@param s, "String" String to split into blocks with size > 1
@param n, "Number of bytes" Int representing max. block size

@return List containing blocks
"""
def split_blocks(s, n):
    if len(s) < 1:
        raise EncodeError("Cannot split an empty block", s)
    elif n < 1:
        raise EncodeError("Must split blocks into 1 or more", n)

    if len(s) < n:
        return [s]

    result = []
    for i in range(0, len(s), n):
        r = s[i:i + n]
        result += [r]
    return result


"""
@brief Pads string a string to a larger size using given padding

@param b, "Block" String to up-size
@param n, "Bytes" Int number of bytes new string should contain (n > len(b))
@param c, "Character" String to pad remaining spaces

@return String with length n (b || [c]^n)
"""
def pad_block(b, n, c):
    # Check c?
    last_block_size = len(b)
    if last_block_size == n:
        return b
    elif last_block_size > n:
        raise EncodeError("Block larger than padding length", b)
    elif last_block_size <= 0:
        raise EncodeError("Block empty", b)
    elif last_block_size < n:
        for i in range(last_block_size + 1, n + 1):
            b += c
    return b


"""
XOR's two strings together.

@param s1, "String 1"
@param s2, "String 2"

@return String
"""
def xor_string(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


"""
@brief Use of Feistel Cipher algorithm to encode cipher.

@param data, String to be encoded
@param keys, List of keys for hash function

@return String containing cipher where 
(len(cipher) == len(data) or len(data) + 1)
"""
def encode(data, keys):
    s = split(data)  ## Split cleartext into two equal size pieces

    for key in keys:
        # Ensure: len(f) == len(s[1]); ie. returns the same length string
        f = encode_function(s[1], key)
        # Ensure: s[0] = XOR s[0], f
        s[0] = xor_string(s[0], f)
        s[0], s[1] = s[1], s[0]

    cipher = s[1] + s[0]
    return cipher


"""
@brief Use of Feistel Cipher algorithm to decode cipher.
Similar to encode function, but keys are reversed.

@param data, String hash to be decoded
@param keys, List of keys for hash function

@return String containing decoded cipher where 
(len(original_cleartext) == len(decoded_cipher))
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

    cleartext = s[1] + s[0]

    # If cleartext ends with a space, it was unbalanced before: Remove padding
    if cleartext[-1] == PADDING:
        cleartext = cleartext[:-1]
    return cleartext


"""
@brief Opens a file and returns the text.

@param f_path, "File path" String containing where <source>.txt is located

@return String containing <source>.txt contents
"""
def get_source_txt(f_path):
    file = open(f_path, "r")
    data = file.read()
    file.close()
    return data


"""
@brief Writes data to a file and handles overwriting an existing file.

@param f_path, "File path" String containing where <destination>.txt is located
@param data, String containing data to be written to <destination>.txt
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
Handles program arguments and exits program.

@param reason, String containing reason for error
"""
def usage_error(reason):
    print(reason)
    usage()
    exit(1)


"""
Prints correct way to input arguments for program.
"""
def usage():
    print("Usage: feistel_cipher.py "
          "[-h|--help] "
          "-[e|d] "
          "[-s <source> | --src <source.txt>] "
          "[-k <keys> | --ksrc <keys.txt>] "
          "--dst <destination.txt>")


"""
Prints help message containing instructions for program.
"""
def help():
    print("HELP PLACEHOLDER")


if __name__ == '__main__':
    encoding, decoding = False, False
    s, src, k, ksrc, dst = '', '', '', '', ''
    opts = []

    # Parse arguments
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "heds:k:",
            ["help", "src=", "ksrc=", "dst="]
        )
    except getopt.GetoptError as err:
        print(err)
        exit(1)

    # TODO check valid characters?
    for o, a in opts:
        if o in ("-h", "--help"):
            help()
            exit()
        elif o == "-e":
            encoding = True
        elif o == "-d":
            decoding = True
        elif o == "-s":
            s = a
        elif o == "--src":
            src = a
        elif o == "-k":
            k = a
        elif o == "--ksrc":
            ksrc = a
        elif o == "--dst":
            dst = a
        else:
            usage_error("Argument not recognised")

    if not (encoding or decoding):
        usage()
        exit()

    # Check works
    if not (encoding ^ decoding):
        print("Provide either encoding or decoding.")
        exit()

    if not (s or src):
        print("Provide source.")
        exit()
    elif s and src:
        print("Provide either s or src, not both.")
        exit()

    if not (k or ksrc):
        print("Provide keys.")
        exit()
    elif k and ksrc:
        print("Provide either k or ksrc, not both.")
        exit()

    # Get keys as string
    keys = ""
    if ksrc:
        # Check validity
        keys = get_source_txt(ksrc)
        keys = keys.splitlines()
    else:
        # Check validity
        keys = k.split(KEY_SPLIT)

    # Get source as string
    if src:
        if src[-4:] != ".txt":
            usage_error(f'file: {src} must be a .txt file')
        s = get_source_txt(src)

    # Encode or decode
    result = ""
    if encoding and s:
        result = encode(s, keys)
    elif decoding and s:
        result = decode(s, keys)
    else:
        # Should never reach here
        exit()

    # If dst provied: Save results in <dst>.txt
    # Check validity
    if dst:
        set_textfile(dst, result)
    else:
        print("Result=" + result)

    exit()