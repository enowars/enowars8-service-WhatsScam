import rsa
import sympy
import base64

#from gmpy2 import is_prime
from . import call_c


first_primes_list = list(sympy.primerange(2, 10000))

# Generate RSA key pair
def generate_key_pair(p,q):
    n = p * q
    e = 65537  # Commonly used public exponent
    d = rsa.common.inverse(e, (p-1)*(q-1))
    # Generate RSA key object
    private_key = rsa.PrivateKey(n, e, d, p, q)
    public_key = rsa.PublicKey(n, e)
    return private_key, public_key


def get_keys():
    p,q = call_c.get_prime_from_c()
    private_key, public_key = generate_key_pair(p,q)
    return private_key.save_pkcs1().decode(), public_key.save_pkcs1().decode()


async def encryption_of_message(message, public_key):
    byte_len = 52
    public_key = rsa.PublicKey.load_pkcs1(public_key.encode())
    message = message.encode('utf-8')
    message_chunks = [message[i:i+byte_len] for i in range(0, len(message), byte_len)]
    cipher_string = b""
    for i in range(len(message_chunks)):
        cipher = rsa.encrypt(message_chunks[i], public_key)
        cipher_string += cipher
    return base64.b64encode(cipher_string).decode()

def decryption_of_message(cipher_string, private_key):
    byte_len = 64   
    private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    cipher_string = base64.b64decode(cipher_string)
    cipher_array = [cipher_string[i:i+byte_len] for i in range(0, len(cipher_string), byte_len)]
    plaintext = ""
    for cipher in cipher_array:
        plaintext += rsa.decrypt(cipher, private_key).decode()
    return plaintext

