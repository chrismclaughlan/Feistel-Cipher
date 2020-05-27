# Feistel-Cipher

```Usage: feistel-cipher.py -[e|d] <file.txt> -s```


```New usage: feistel_cipher.py [-h|--help] -[e|d] [-s|--src] <source.txt> [-k|--keys] <keys.txt> [-d|--dst] <destination.txt>```


Encodes and decodes source.txt files using Feistel Cipher algorithm and 
BLAKE2b hash function and saves result into desination.txt

Change SECRET key!

### Keys
- Max. length = 64 bytes
- Multiple keys seperated by space " "

## Secret Key
- Max. length = 64 bytes

## Todo
- check key < 64 bytes
- Error handling for file opening
- check valid input text (ascii)