from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import datetime
import base64

def random_number():
    random_number = random.randint(0, 2**128 - 1)
    return random_number.to_bytes(16, byteorder='big')

def aes_encrypt(plaintext):
    current_time = datetime.datetime.now().time()
    time_str = str(current_time)
    time = time_str.split(':')
    seed = time[0] + time[1]
    random.seed(seed)

    key = random_number()
    nonce = random_number()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = plaintext.encode()
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode(), key, nonce















