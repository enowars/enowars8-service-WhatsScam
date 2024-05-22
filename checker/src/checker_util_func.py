from asyncio import StreamReader, StreamWriter
import asyncio
import random
import string
#import faker


from httpx import AsyncClient
from typing import Optional
from logging import LoggerAdapter
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import datetime
import rsa
import math


from Crypto.Cipher import AES
import checker_util_func
import rsa
import base64




from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    FlagSearcher,
    BaseCheckerTaskMessage,
    PutflagCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    InternalErrorException,
    PutflagCheckerTaskMessage,
    AsyncSocket,
)
from enochecker3.utils import assert_equals, assert_in



#util functions 


async def create_user(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    public_key: Optional[str] = None,    
) -> None:
    
    email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + "@example.com"
    firstName = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    password1 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    password2 = password1
    logger.info(f"Creating user with email: {email} firstName: {firstName} password1: {password1} password2: {password2}")
    logger.info(f"public_key on?: {public_key}")

    response = await client.post(
        "/sign-up",
        data={
            "email": email,
            "firstName": firstName,
            "public_key": public_key,
            "password1": password1,
            "password2": password2,
        },
        follow_redirects=True,
    )

    print("email: ", email)
    print("firstName: ", firstName)
    print("password1: ", password1)
    print("password2: ", password2)
    print("public_key: ", public_key)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    print("hier response von create user")
    print(response.text)

    assert_equals(100 < response.status_code < 300, True, "Creating user failed")

    return email, password1

async def login_user(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str,
    password: str,
) -> None:
    logger.info(f"Logging in with email: {email} password: {password}")

    response = await client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Logging in failed")


async def create_note(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    note: str,
    public_key: str,
) -> None:
    logger.info(f"Creating note: {note} with public key: {public_key}")

    response = await client.post(
        "/",
        data={"note": note, "public_key": public_key},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Creating note failed")

async def get_note(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    note: str,
) -> None:
    logger.info(f"Getting note")

    response = await client.get(f"/", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting note failed")

    soup = BeautifulSoup(response.text, "html.parser")
    assert_in(note, soup.text, "Getting note failed")


async def logout(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Logging out")

    response = await client.get("/logout", follow_redirects=True)# change to get if error
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Logging out failed")

async def get_user_of_userlist(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str, 
) -> None:
    print("diese email: ", email)
    logger.info(f"Getting user of userlist")
    response = await client.get("/userlist", follow_redirects=True)

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting user of userlist failed")

    soup = BeautifulSoup(response.text, "html.parser")
    li = soup.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = filter(lambda x: email + '\n' in x, li)
    li = filter(lambda x: x != '' and x != '\n' and x != email + '\n', list(li)[0])
    public_key = list(li)
    return public_key[0].strip()



    # soup = BeautifulSoup(response.text, "html.parser")
    # print("soup: ", soup)
    # li = soup.find_all("li")
    # print("buggy li: ", li)
    # li = [x.text for x in li]
    # print("text1 li: ", li)
    # li = [x.split(" ") for x in li]
    # print("split2 li: ", li)
    # li = filter(lambda x: email + '\n' in x, li)
    # print("filter1 li: ", list(li)[0])
    # li = filter(lambda x: x != '' and x != '\n' and x != email + '\n', list(li)[0]) #change to list with 1 element 
    # print("filter2 li: ", list(li))
    # public_key = list(li)
    # #print(public_key[0].strip())
    

    # return public_key[0].strip()

async def get_all_notes(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    note: str,
) -> None:
    logger.info(f"Getting all notes")

    response = await client.get("/", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting all notes failed")

    soup = BeautifulSoup(response.text, "html.parser")

    return soup

# async def format_rsa_public_key(key_str):
#     key_str = key_str.replace(" ", "").replace("\n", "")
#     formatted_key = "-----BEGIN RSA PUBLIC KEY-----\n"
    
#     # Split the key into 64-character lines
#     for i in range(0, len(key_str), 64):
#         formatted_key += key_str[i:i+64] + "\n"
    
#     formatted_key += "-----END RSA PUBLIC KEY-----\n"
#     return formatted_key

# async def decryption_of_message(cipher_string, private_key):
#     private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
#     cipher_string = cipher_string.decode('utf-8')
#     cipher_string = cipher_string.encode('latin-1')
#     cipher_array = [cipher_string[i:i+64] for i in range(0, len(cipher_string), 64)]
#     plaintext = ""
#     for cipher in cipher_array:
#         plaintext += rsa.decrypt(cipher, private_key).decode()
#     return plaintext

def format_rsa_public_key(key_str):
    byte_len = 32 #64
    key_str = key_str.replace(" ", "").replace("\n", "")
    formatted_key = "-----BEGIN RSA PUBLIC KEY-----\n"
    
    # Split the key into 64-character lines
    for i in range(0, len(key_str), byte_len):
        formatted_key += key_str[i:i+byte_len] + "\n"
    
    formatted_key += "-----END RSA PUBLIC KEY-----\n"
    return formatted_key

def decryption_of_message(cipher_string, private_key):
    byte_len = 32 #64
    print("cipher_string: ", cipher_string)
    print("private_key: ", private_key)
    private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    cipher_string = base64.b64decode(cipher_string)
    cipher_array = [cipher_string[i:i+byte_len] for i in range(0, len(cipher_string), byte_len)]
    plaintext = ""
    for cipher in cipher_array:
        plaintext += rsa.decrypt(cipher, private_key).decode()
    print("plaintext: ", plaintext)
    return plaintext

def expprime(publickey):
    n = publickey.n
    e = publickey.e
    p = math.isqrt(n + 4)-2
    q = p + 4
    # Calculate private exponent
    d = rsa.common.inverse(e, (p-1)*(q-1))

    # Generate RSA key object
    private_key = rsa.PrivateKey(n, e, d, p, q)
    return private_key

############################################################################################################
# 2 exploit here

async def create_group(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    group_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    logger.info(f"Creating group: {group_name}")
    group_key = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    logger.info(f"Creating group with key: {group_key}")

    response = await client.post(
        "/creategroup",
        data={"group_name": group_name, "group_key": group_key, "add_group": "add_group"},
        follow_redirects=True,
    )
    redirect_url = response.url

    logger.info(f"Redirect URL: {redirect_url}")

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Creating group failed")

    return group_name, group_key, redirect_url

async def create_group_note(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    note: str,
    redirect_url: str,
) -> None:
    logger.info(f"Creating note: {note}")

    response = await client.post(
        redirect_url,
        data={"note_of_group": note},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Creating note failed")


async def join_group(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    group_name: str,
    group_key: str,
    group_id: str,
) -> None:
    logger.info(f"Getting group note")
    response = await client.post(
        "/creategroup",
        data={"group_key_join_" + str(group_id): group_key, "join_group": group_id},
        follow_redirects=True,
    )

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    print("response: ", response.text)
    assert_equals(100 < response.status_code < 300, True, "Getting group note failed")

async def get_group_note(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    group_name: str,
    group_key: str,
    group_id: str,
    note: str,
) -> None:
    logger.info(f"Getting group note")

    response = await client.get("/creategroup/" + str(group_id), follow_redirects=True)

    print("response: ", response.text)

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting group note failed")

    soup = BeautifulSoup(response.text, "html.parser")
    assert_in(note, soup.text, "Getting group note failed")

async def open_group_window(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    group_id: str,
) -> None:
    logger.info(f"Opening group window")
    response = await client.get("/creategroup/" + str(group_id), follow_redirects=True)
    print("hier responseeee")
    print(group_id)
    print("addr: ", "/creategroup/" + str(group_id))
    print("response: ", response.text)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Opening group window failed")
    
    return response

def key_exploit(seed):
    random.seed(seed)
    def not_so_random():
        random_number = random.randint(0, 2**128 - 1)
        return random_number.to_bytes(16, byteorder='big')

    key = not_so_random()
    nonce = not_so_random()
    return key, nonce

def insecure_aes_decrypt(ciphertext, seed):
    seed = seed
    key, nonce = key_exploit(seed)
    ciphertext = base64.b64decode(ciphertext) 
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext

async def exploit2(
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    cipher: str,
    seed: str,
    searcher: FlagSearcher,
) -> None:
    for hour in range(24):      
        for minute in range(60):
            try:
                formatted_time = f"{hour:02d}{minute:02d}"
                formatted_time = str(formatted_time)
                plaintext = insecure_aes_decrypt(cipher, seed=formatted_time)
                print("plaintexttt")
            
                if flag := searcher.search_flag(plaintext.decode()):
                    return flag
            except:
                pass

    


    