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
def parse0(message):
    message = [n.strip() for n in message.split('\n')]
    message = list(filter(lambda x: x != '', message))
    print(message)
    print("das sind die base message")
    print(message[2])
    all = message[2]
    l = all.split(' ')
    date = l[0]
    time = l[1]
    return {"content:": message[1], "date": date, "time": time}

def parse1(message):
    message = [n.strip() for n in message.split('\n')]
    message = list(filter(lambda x: x != '', message))
    all = message[1]
    l = all.split(' ')
    date = l[0]
    time = l[1]
    return {"content:": message[0], "date": date, "time": time}

############################################################################################################



#havoc checked
# for non public key 0.05
async def create_user(
    client: AsyncClient,
    logger: LoggerAdapter,
    public_key: Optional[str] = None,    
) -> None:
    
    # For later documentation this seed has to be set random because of threading issues from checker exploit 0 and 1 which generate the same email if seed is used normaly (seed exploit?)
    random.seed(random.SystemRandom().random())
    email = "".join(random.choices(string.ascii_letters + string.digits, k=20)) + "@example.com"
    name = "".join(random.choices(string.ascii_letters + string.digits, k=20))
    password1 = "".join(random.choices(string.ascii_letters + string.digits, k=20))
    password2 = password1
    logger.info(f"Creating user with email: {email} name: {name} password1: {password1} password2: {password2}")
    logger.info(f"public_key on?: {public_key}")

    response = await client.post(
        "/sign-up",
        data={
            "email": email,
            "name": name,
            "public_key": public_key,
            "password1": password1,
            "password2": password2,
        },
        follow_redirects=True,
        #timeout=3.0, #standard timeout 5.0
    )

    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Creating user failed")

    return email, password1

#havoc checked
async def login_user(
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

#havoc checked
async def create_message(
    client: AsyncClient,
    logger: LoggerAdapter,
    message: str,
    public_key: str,
) -> None:
    logger.info(f"Creating message: {message} with public key: {public_key}")

    response = await client.post(
        "/",
        data={"message": message, "public_key": public_key},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Creating message failed")

#havoc checked
async def get_message(
    client: AsyncClient,
    logger: LoggerAdapter,
    message: str,
) -> None:
    logger.info(f"Getting message")

    response = await client.get(f"/", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting message failed")

    soup = BeautifulSoup(response.text, "html.parser")
    assert_in(message, soup.text, "Getting message failed")

#havoc checked
#0.02s
async def logout(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Logging out")

    response = await client.get("/logout", follow_redirects=True)# change to get if error
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Logging out failed")

#havoc checked
async def get_user_of_userlist(
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str, 
) -> None:
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
    return public_key[2].strip()

#havoc checked
async def get_all_messages(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Getting all messages")

    response = await client.get("/", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting all messages failed")

    soup = BeautifulSoup(response.text, "html.parser")

    return soup

#checked
async def get_message_time0(
    client: AsyncClient,
    logger: LoggerAdapter,
    message: str,
    dir: str,
) -> None:
    logger.info(f"Getting message time")

    response = await client.get(dir, follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting message time failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    messages = [parse0(message) for message in messages]
    for n in messages:
        if n['content:'] == message:
            print("das ist die zeit", n['time'])
            return n['time']
        
async def get_message_time1(
    client: AsyncClient,
    logger: LoggerAdapter,
    message: str,
    dir: str,
) -> None:
    logger.info(f"Getting message time")

    response = await client.get(dir, follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting message time failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    messages = [parse1(message) for message in messages]
    for n in messages:
        if n['content:'] == message:
            print("das ist die zeit", n['time'])
            return n['time']

#checked
#0.02s
async def time_correct0(
    client: AsyncClient,
    logger: LoggerAdapter,
    time: str,
    dir: str,
) -> None:
    logger.info(f"Checking time")

    response = await client.get(dir, follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Checking time failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    messages = [parse0(message) for message in messages]
    if time in [n['time'] for n in messages]:
        return True
    else:
        return False
    
async def time_correct1(
    client: AsyncClient,
    logger: LoggerAdapter,
    time: str,
    dir: str,
) -> None:
    logger.info(f"Checking time")

    response = await client.get(dir, follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Checking time failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    messages = [parse1(message) for message in messages]
    if time in [n['time'] for n in messages]:
        return True
    else:
        return False

#checked
async def get_private_key(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> str:
    logger.info(f"Getting private key")

    response = await client.get("/profil", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting private key failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    single_string = ''.join(messages)
    private_key = single_string.split("Your Privatekey (DO NOT SHARE):")
    return private_key[1]#.replace('\n', '')

#checked
async def try_private_key(
    client: AsyncClient,
    logger: LoggerAdapter,
    private_key: str,
    message: str,
) -> None:
    logger.info(f"Getting message time")
    private_key = private_key.replace("\\n", "\n")

    response = await client.get(f"/", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting message time failed")

    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    messages = [parse0(message) for message in messages]
    key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    private_key = key.save_pkcs1().decode()
    for n in messages:
        try:
            plaintext = decryption_of_message(n['content:'], private_key)
            if plaintext == message:
                return True
        except:
            pass
    return False
    

#havoc checked
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

#havoc checked
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


#havoc checked
def expprime(publickey):
    n = publickey.n
    e = publickey.e
    p = math.isqrt(n + 4)-2
    q = p + 6
    # Calculate private exponent
    d = rsa.common.inverse(e, (p-1)*(q-1))

    # Generate RSA key object
    private_key = rsa.PrivateKey(n, e, d, p, q)
    return private_key

############################################################################################################
# 2 exploit here

async def create_group(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    random.seed(random.SystemRandom().random())
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

async def create_group_message(
    client: AsyncClient,
    logger: LoggerAdapter,
    message: str,
    redirect_url: str,
) -> None:
    logger.info(f"Creating message: {message}")

    response = await client.post(
        redirect_url,
        data={"message_of_group": message},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Creating message failed")


#0.04s
async def join_group(
    client: AsyncClient,
    logger: LoggerAdapter,
    group_name: str,
    group_key: str,
    group_id: str,
) -> None:
    logger.info(f"Getting group message")
    response = await client.post(
        "/creategroup",
        data={"group_key_join_" + str(group_id): group_key, "join_group": group_id},
        follow_redirects=True,
    )

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting group message failed")

#0.02s
async def get_group_message(
    client: AsyncClient,
    logger: LoggerAdapter,
    group_name: str,
    group_key: str,
    group_id: str,
    message: str,
) -> None:
    logger.info(f"Getting group message")

    response = await client.get("/creategroup/" + str(group_id), follow_redirects=True)

    logger.info(f"Server answered: {response.status_code} - {response.text}")
    assert_equals(100 < response.status_code < 300, True, "Getting group message failed")

    soup = BeautifulSoup(response.text, "html.parser")
    assert_in(message, soup.text, "Getting group message failed")

async def open_group_window(
    client: AsyncClient,
    logger: LoggerAdapter,
    group_id: str,
) -> None:
    logger.info(f"Opening group window")
    response = await client.get("/creategroup/" + str(group_id), follow_redirects=True)
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
            
                if flag := searcher.search_flag(plaintext.decode()):
                    return flag
            except:
                pass

#not checked
async def decrypt_aes(
    client: AsyncClient,
    logger: LoggerAdapter,
    cipher: str,
    key: str,
    nonce: str,
    randommessage: str,
    response: str,
) -> bool:
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        ciphertext_array = soup.find_all('li', class_='list-group-item')
        ciphertext_array = [cipher.text for cipher in ciphertext_array]
        ciphertext_array = [parse1(cipher) for cipher in ciphertext_array]
    except:
        raise MumbleException("Could not open group window")
    
    try:
        for cipher_text in ciphertext_array:
            try:
                ciphertext = cipher_text['content:'] 
                ciphertext = base64.b64decode(ciphertext)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, AES.block_size)
                if plaintext == randommessage.encode():
                    return True
            except:
                pass    
    except:
        raise MumbleException("Could not decrypt message properly")
    
    return False

############################################################################################################

#here havoc helper functions

async def profile(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Changing profile")

    response = await client.get(
        "/profil",
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Changing profile failed")
    return response

async def profile_change_status(
    client: AsyncClient,
    logger: LoggerAdapter,
    status: str,
) -> None:
    logger.info(f"Changing profile status")

    response = await client.post(
        "/profil",
        data={"status": status},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Changing profile status failed")
    
async def profile_get_private_key(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Getting private key")

    response = await client.post(
        "/profil",
        data={"public_key": "on"},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Getting private key failed")
    return response


############################################################################################################
#utils for func 3

async def get_token(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Getting token")

    response = await client.post(
        "/profil",
        data = {"token": "on"},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Getting token failed")
    return response
    
async def get_token_from_backup(
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str,
    token: str,
) -> None:
    logger.info(f"Getting token from backup")

    response = await client.post(
        "/backup",
        data = {"email_backup": email, "token_backup": token},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Getting token from backup failed")
    return response

async def create_user_backup(
    client: AsyncClient,
    logger: LoggerAdapter,
    public_key: Optional[str] = None,    
) -> None:
    
    # For later documentation this seed has to be set random because of threading issues from checker exploit 0 and 1 which generate the same email if seed is used normaly (seed exploit?)
    random.seed(random.SystemRandom().random())
    email = "".join(random.choices(string.ascii_letters + string.digits, k=20)) + "@scam.com"
    name = "".join(random.choices(string.ascii_letters + string.digits, k=20))
    password1 = "".join(random.choices(string.ascii_letters + string.digits, k=20))
    password2 = password1
    logger.info(f"Creating user with email: {email} name: {name} password1: {password1} password2: {password2}")
    logger.info(f"public_key on?: {public_key}")

    response = await client.post(
        "/sign-up",
        data={
            "email": email,
            "name": name,
            "public_key": public_key,
            "password1": password1,
            "password2": password2,
        },
        follow_redirects=True,
        #timeout=3.0, #standard timeout 5.0
    )

    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Creating user failed")

    return email, password1

async def event(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    logger.info(f"Getting event")

    response = await client.get(
        "/flag",
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    if "https://www.youtube.com/shorts/GcUPwqoIEYk" not in response.text:
        raise MumbleException("Getting event failed")

    assert_equals(100 < response.status_code < 300, True, "Getting event failed")
    return True

async def add_friend(
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str,
) -> None:
    logger.info(f"Adding friend")

    response = await client.post(
        "/add_friend",
        data = {"friend_email": email, "add_friend": "add_friend"},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Adding friend failed")
    return response

async def accept_friend(
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str,
) -> None:
    logger.info(f"Accepting friend")

    response = await client.post(
        "/add_friend",
        data = {"accept_friend": email},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Accepting friend failed")
    return response

async def reject_friend(
    client: AsyncClient,
    logger: LoggerAdapter,
    email: str,
) -> None:
    logger.info(f"Rejecting friend")

    response = await client.post(
        "/add_friend",
        data = {"reject_friend": email},
        follow_redirects=True,
    )
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Rejecting friend failed")
    return response


    


    
    