from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import time
import datetime
import exploit


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
print("Key:", key)
print("Nonce:", nonce)

def insecure_aes_encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


if __name__ == '__main__':
    #Example:
    plaintext = b'Enoflag'
    print("Plaintext:" + str(plaintext))
    ciphertext = insecure_aes_encrypt(plaintext)
    exploit.insecure_aes_decrypt(ciphertext)









