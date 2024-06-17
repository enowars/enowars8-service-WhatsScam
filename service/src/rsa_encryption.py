import rsa
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import random
import sympy
import time 
import pickle
import base64

#change it back just for now bc main.py is not working localy
from gmpy2 import is_prime

# the prime calculation is based on https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/
# First 10000 prime numbers


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

# Generate a random n-bit number
def nBitRandom(n):
    random.seed(random.SystemRandom().random())
    return random.randrange(2**(n-1)+1, 2**n - 1)
 
 
def getLowLevelPrime(n):
    while True:
        # Obtain a random number
        randomnumber = nBitRandom(n)
        randomnumber2 = randomnumber + 4
 
        # test if number is prime
        for divisor in first_primes_list:
            if randomnumber % divisor == 0 and divisor**2 <= randomnumber or randomnumber2 % divisor == 0 and divisor**2 <= randomnumber2:
                break
        else:
            return randomnumber, randomnumber2

 
def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 
    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True
 
 
def random_prime():
  def test(p,q):
    for _ in first_primes_list:
      if p % _ == 0 or q % _ == 0: return False 
    return True
  while True:
    p = nBitRandom(256)
    p |= 1
    q = p + 6 
    if test(p,q):
      if is_prime(p) and is_prime(q): return p,q
      #if isMillerRabinPassed(p) and isMillerRabinPassed(q): return p,q



def get_keys():
    p,q = random_prime()
    private_key, public_key = generate_key_pair(p,q)
    return private_key.save_pkcs1().decode(), public_key.save_pkcs1().decode()


async def encryption_of_message(message, public_key):
    #make 52 byte/char long messages and add them together to make bigger
    #byte_len = 20 
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
    #byte_len = 32 #64
    byte_len = 64   
    private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    cipher_string = base64.b64decode(cipher_string)
    cipher_array = [cipher_string[i:i+byte_len] for i in range(0, len(cipher_string), byte_len)]
    plaintext = ""
    for cipher in cipher_array:
        plaintext += rsa.decrypt(cipher, private_key).decode()
    return plaintext

# if __name__ == '__main__':
#     message = "ENOABCDEF1234567890+/=ABCDEFGHIJKLM1234567890+/=1234567890+/="
#     private_key, public_key = get_keys()
#     cipher_string = encryption_of_message(message, public_key)
#     plaintext = decryption_of_message(cipher_string, private_key)
#     print("Plaintext: ", plaintext)
