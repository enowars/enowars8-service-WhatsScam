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
from Crypto.Cipher import AES
import rsa
import base64
from Crypto.Util.Padding import pad, unpad



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

#timeout = 5.0
timeout = 10.0


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
    start_time = datetime.datetime.now()
    
    success = True
    start = datetime.datetime.now()
    for i in range(0, 4):
        try:
            email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on', timeout = timeout)
            break
        except:
            print("time taken: ", datetime.datetime.now() - start)  
            success = False

    if not success:
        raise MumbleException("Could not create user 1")
    

    success = True
    for i in range(0, 4):
        try:
            await checker_util_func.logout(client, logger)
            break
        except:
            success = False
    if not success:
        raise MumbleException("Could not logout")

    start_time2 = datetime.datetime.now()
    success = True
    for i in range(0, 4):
        try:
            email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key= None)
            break
        except:
            success = False

    if not success:
        raise MumbleException("Could not create user 2")
    

    for i in range(0, 2):
        try:
            public_key = await checker_util_func.get_user_of_userlist( client, logger, email = email_1)
            break
        except:
            raise MumbleException("Could not get public key")


    note = str(task.flag)
    target_email = email_1
    for i in range(0, 2):
        try:
            await checker_util_func.create_note(client, logger, note, public_key)
            break
        except:
            raise MumbleException("Could not create note")
    for i in range(0, 2):
        try:
            await db.set("user_data_0", (email_2, password1_2))
            break
        except:
            raise MumbleException("Could not set userdata")

    end_time = datetime.datetime.now()

    return email_1


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    start_time = datetime.datetime.now()

    for i in range(0, 2):
        try:
            email, password = await db.get("user_data_0")
            break
        except KeyError:
            raise MumbleException("Missing database entry from putflag")
    
    for i in range(0, 2):
        try:
            await checker_util_func.login_user(client, logger, email, password)
            break
        except:
            raise MumbleException("Could not login user")
        
    for i in range(0, 2):
        try:
            await checker_util_func.get_note( client, logger, note = str(task.flag))
            break
        except:
            raise MumbleException("Could not get note")
    end_time = datetime.datetime.now()


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
    success = True
    for i in range(0, 4):
        try:
            email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
            break
        except:
            success = False

    if not success:
        raise MumbleException("Could not create user 3")
        
    for i in range(0, 2):
        try:
            public_key = await checker_util_func.get_user_of_userlist(client, logger, email = target_email)
            break
        except:
            raise MumbleException("Could not get public key")
    
    for i in range(0, 2):
        try:
            public_key = checker_util_func.format_rsa_public_key(public_key)
            break
        except:
            raise MumbleException("Could not format public key")
    
    key = rsa.PublicKey.load_pkcs1(public_key.encode())
    for i in range(0, 2):
        try:
            private_key = checker_util_func.expprime(key)
            break
        except:
            raise MumbleException("Could not create private key")
    private_key = private_key.save_pkcs1().decode()

    for i in range(0, 2):
        try:
            get_all_notes = await checker_util_func.get_all_notes(client, logger)
            break
        except:
            raise MumbleException("Could not get all notes")
    soup_html = get_all_notes #BeautifulSoup(get_all_notes, "html.parser")
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
    
    start = datetime.datetime.now()
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on', timeout = timeout)
    except:
        print("time taken: ", datetime.datetime.now() - start)  
        raise MumbleException("Could not create user 1")
    try:
        private_key = await checker_util_func.get_private_key(client, logger)
    except:
        raise MumbleException("Could not get private key")
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")

    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 2")
    
    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email_1)
    except:
        raise MumbleException("Could not get public key")

    random.seed(random.SystemRandom().random())
    randomNumber = random.randint(10, 1000)
    randomNote = "".join(random.choices(string.ascii_letters + string.digits, k=randomNumber))
    try:
        await checker_util_func.create_note(client, logger, randomNote, public_key)
    except:
        raise MumbleException("Could not create note")
    
    try:
        time = await checker_util_func.get_note_time(client, logger, note = randomNote, dir = "/")
        if time == None:
            raise MumbleException("Could not get note time")
    except:
        raise MumbleException("Could not get note time")


    
    try:
        await db.set("user_data_0_noise", (email_2, password1_2, randomNote, time, private_key))
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
        email, password, Note, time, private_key = await db.get("user_data_0_noise")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    try:
        await checker_util_func.login_user(client, logger, email, password)
    except:
        raise MumbleException("Could not login user")
    
    try:
        await checker_util_func.get_note(client, logger, note = str(Note))
    except:
        raise MumbleException("Could not get note")
    
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    
    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user")
    
    try:
        boolean = await checker_util_func.time_correct(client, logger, time, dir = "/")
        if not boolean:
            raise MumbleException("Time is not correct or encrypted note is not there")
    except:
        raise MumbleException("Could not check time")
    try:
        boolean = await checker_util_func.try_private_key(client, logger, private_key, str(Note))
        if not boolean:
            raise MumbleException("Could not use private key")
    except:
        raise MumbleException("Could not use private key")
    

@checker.havoc(0)
async def havoc0(
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    start = datetime.datetime.now()
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on', timeout = timeout)
    except:
        print("time taken: ", datetime.datetime.now() - start)  
        raise MumbleException("Could not create user 1 with public key")
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    try:
        await checker_util_func.login_user(client, logger, email_1, password1_1)
    except:
        raise MumbleException("Could not login user")
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 2 without public key")
    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email_1)
    except:
        raise MumbleException("Could not get public key of user 1")
    try:
        await checker_util_func.create_note(client, logger, "havoc", public_key)
    except:
        raise MumbleException("Could not create note with public key")
    try:
        await checker_util_func.get_note(client, logger, note = "havoc")
    except:
        raise MumbleException("Could not get note with public key")
    try:
        all_notes = await checker_util_func.get_all_notes(client, logger)
    except:
        raise MumbleException("Could not get all notes")


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
    except:
        raise MumbleException("Could not create user 1")
    for i in range(0, 2):
        try:
            group_name, group_key, redirect_url = await checker_util_func.create_group(client, logger)
            break
        except:
            pass
    group_id = str(redirect_url).split('/')[-1]
    try:
        await checker_util_func.create_group_note(client, logger, note = task.flag, redirect_url = redirect_url)
    except:
        raise MumbleException("Could not create group note")
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
    except:
        raise MumbleException("Could not create user")
    try:
        await checker_util_func.join_group(client, logger, group_name, group_key, group_id)
    except:
        raise MumbleException("Could not join group")
    try:
        await checker_util_func.get_group_note(client, logger, group_name, group_key, group_id, note = task.flag)
    except:
        raise MumbleException("Could not get group note")

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
    except:
        raise MumbleException("Could not create user 1")
    try:
        group_name, group_key, redirect_url = await checker_util_func.create_group(client, logger)
    except:
        pass
    group_id = str(redirect_url).split('/')[-1]


    random.seed(random.SystemRandom().random())
    randomNumber = random.randint(10, 1000)
    randomNote = "".join(random.choices(string.ascii_letters + string.digits, k=randomNumber))
    try:
        await checker_util_func.create_group_note( client, logger, note = randomNote, redirect_url = redirect_url)
    except:
        raise MumbleException("Could not create group note")
    try:
        time_db = await checker_util_func.get_note_time(client, logger, note = randomNote, dir= redirect_url)
    except:
        raise MumbleException("Could not get note time")
    
    #calculate key, nonce
    # try:
    #     time_str = str(time_db)
    #     time_calc = time_str.split(':')
    #     seed = time_calc[0] + time_calc[1]
    #     random.seed(seed)
    #     key = random.randint(0, 2**128 - 1).to_bytes(16, byteorder='big')
    #     nonce = random.randint(0, 2**128 - 1).to_bytes(16, byteorder='big')
    # except:
    #     raise MumbleException("Could not calculate key and nonce")
    
    try:
        #await db.set("group_data_1_noise", (group_name, group_key, group_id, randomNote, time_db, key, nonce))
        await db.set("group_data_1_noise", (group_name, group_key, group_id, randomNote, time_db))
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
        #group_name, group_key, group_id, randomNote, time, key, nonce = await db.get("group_data_1_noise")
        group_name, group_key, group_id, randomNote, time = await db.get("group_data_1_noise")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user")

    try:
        await checker_util_func.join_group(client, logger, group_name, group_key, group_id)
    except:
        raise MumbleException("Could not join group")
    
    try:
        await checker_util_func.get_group_note(client, logger, group_name, group_key, group_id, note = randomNote)
    except:
        raise MumbleException("Could not get group note")
    
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user")
    try:
        url = "/creategroup/" + group_id
        boolean = await checker_util_func.time_correct(client, logger, time, dir = url)
        if not boolean:
            raise MumbleException("Time is not correct or encrypted note is not there")
    except:
        raise MumbleException("Could not check time")
    
    # try:
    #     response = await checker_util_func.open_group_window(client, logger, group_id)
    # except:
    #     raise MumbleException("Could not open group window")

    # try:
    #     bool = await checker_util_func.decrypt_aes(client, logger, response, key, nonce, randomNote, response)
    #     if not bool:
    #         raise MumbleException("Could not decrypt aes or encrypted note is not there")
    # except:
    #     raise MumbleException("Could not decrypt aes or encrypted note is not there")
    


    
if __name__ == "__main__":
    checker.run()