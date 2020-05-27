# Feistel-Cipher

```New usage: feistel_cipher.py [-h|--help] -[e|d] [-s|--src] <source.txt> [-k|--ksrc] <keys.txt> [-d|--dst] <destination.txt>```

Encodes and decodes source.txt files using Feistel Cipher algorithm and 
BLAKE2b hash function and saves result into desination.txt

Number of keys = number of rounds

Example of encoding:
```feistel_cipher.py -e --src resources\text1.txt --ksrc resources\keys.txt --dst resources\output.txt```

Example of decoding:
```feistel_cipher.py -d --src resources\output.txt --ksrc resources\keys.txt --dst resources\output.txt```


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
- kittens are my world ...