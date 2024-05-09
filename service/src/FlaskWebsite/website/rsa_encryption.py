import rsa
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import random
import sympy
import time 
from . import exploit
import pickle

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

    # # Serialize the public and private keys
    # public_key_pem = public_key.save_pkcs1().decode()
    # private_key_pem = private_key.save_pkcs1().decode()
    return private_key, public_key

# Generate a random n-bit number
def nBitRandom(n):
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
    start = time.time()
    while True:
        #n = 512
        n = 256
        prime_candidate, prime_candidate2 = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate) or not isMillerRabinPassed(prime_candidate2):
            continue
        else:
            endtime = time.time()
            print("Time: ", endtime-start)
            if not sympy.isprime(prime_candidate) or not sympy.isprime(prime_candidate2):
                print("Is prime: ", sympy.isprime(prime_candidate))
                print("Is cousin prime: ", sympy.isprime(prime_candidate2))
            return prime_candidate, prime_candidate2

def get_keys():
    p,q = random_prime()
    private_key, public_key = generate_key_pair(p,q)
    return private_key.save_pkcs1().decode(), public_key.save_pkcs1().decode()


def encryption_of_message(message, public_key):
    #make 52 byte/char long messages and add them together to make bigger
    public_key = rsa.PublicKey.load_pkcs1(public_key.encode())
    message_chunks = [message[i:i+52] for i in range(0, len(message), 52)]
    cipher_string = ""
    for i in range(len(message_chunks)):
        cipher = rsa.encrypt(message_chunks[i], public_key)
        cipher_string += cipher.decode('latin-1')  # Convert bytes to string
    return cipher_string

def decryption_of_message(cipher_string, private_key):
    private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    cipher_string = cipher_string.encode('latin-1')
    cipher_array = [cipher_string[i:i+64] for i in range(0, len(cipher_string), 64)]
    plaintext = ""
    for cipher in cipher_array:
        plaintext += rsa.decrypt(cipher, private_key).decode()
    return plaintext

if __name__ == '__main__':
    message = b"ENOABCDEF1234567890+/=ABCDEFGHIJKLM1234567890+/=1234567890+/="
    print("Message: ", message)
    private_key, public_key = get_keys()
    cipher_string = encryption_of_message(message, public_key)
    plaintext = decryption_of_message(cipher_string, private_key)
    print("Plaintext: ", plaintext)

