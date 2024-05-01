# Large Prime Generation for RSA
import random
import sympy
import time 
import rsa_try as rsa
import exploit as exploit
import pickle

# the code is based on https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/
# First 10000 prime numbers


first_primes_list = list(sympy.primerange(2, 10000))

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
 
 
def random_prime(inputs):
    #timearray = []

    for i in range(inputs):
        #start = time.time()
        while True:
            n = 512
            prime_candidate, prime_candidate2 = getLowLevelPrime(n)
            if not isMillerRabinPassed(prime_candidate) or not isMillerRabinPassed(prime_candidate2):
                continue
            else:
                #endtime = time.time()
                if not sympy.isprime(prime_candidate) or not sympy.isprime(prime_candidate2):
                    print("Is prime: ", sympy.isprime(prime_candidate))
                    print("Is cousin prime: ", sympy.isprime(prime_candidate2))
                return prime_candidate, prime_candidate2
    
    #print("Average time: ", sum(timearray)/len(timearray))
                
    


if __name__ == '__main__':
    message = b"ENOABCDEF1234567890+/=ABCDEFGHIJKLM1234567890+/=1234567890+/="
    print("Message: ", message)
    p,q = random_prime(1)
    cipher, private_key, public_key = rsa.generate_key_pair(p,q,message)
    print(exploit.expprime(cipher, public_key))
    

