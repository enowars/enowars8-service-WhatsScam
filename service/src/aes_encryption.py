from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import time
import datetime
from . import exploit


#Patch would be to change the seed to a random value or use a secure random number generator

current_time = datetime.datetime.now().time()
time_str = str(current_time)
time = time_str.split(':')
seed = time[0] + time[1]
random.seed(seed)
print("Seed:", seed)

def not_so_random():
    random_number = random.randint(0, 2**128 - 1)
    return random_number.to_bytes(16, byteorder='big')

key = not_so_random()
nonce = not_so_random()


def insecure_aes_encrypt(plaintext):
    print("Plaintext:", plaintext)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = plaintext.encode()
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    print("Entschlüsselter Text:")
    print(exploit.insecure_aes_decrypt(ciphertext, seed))
    return ciphertext














