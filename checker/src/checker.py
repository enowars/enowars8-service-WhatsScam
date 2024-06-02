from asyncio import StreamReader, StreamWriter
import asyncio
import random
import string
#import faker


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
    print("putflag hier start")
    #timeout = (5.0, 30.0) 
    start_time = datetime.datetime.now()
    
    success = True
    for i in range(0, 4):
        try:
            email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on')
            print(i)
            print("create_user hier")
            break
        except:
            success = False

    if not success:
        raise MumbleException("Could not create user 1")
    

    print("dauer_publickey: ", datetime.datetime.now()-start_time)
    success = True
    for i in range(0, 4):
        try:
            await checker_util_func.logout(client, logger)
            print(i)
            print("logout hier")
            break
        except:
            success = False
    if not success:
        raise MumbleException("Could not logout")

    #print("hey2")
    start_time2 = datetime.datetime.now()
    success = True
    for i in range(0, 4):
        try:
            email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key= None)
            print(i)
            print("create_user hier")
            break
        except:
            success = False

    if not success:
        raise MumbleException("Could not create user 2")
    print("dauer_no_publickey: ", datetime.datetime.now()-start_time2)

    #print("hey3")
    for i in range(0, 2):
        try:
            public_key = await checker_util_func.get_user_of_userlist( client, logger, email = email_1)
            break
        except:
            raise MumbleException("Could not get public key")


    #print("hey4")
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
    print(" : ", end_time-start_time)
    print("putflag hier end")

    return email_1


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> None:
    print("getflag hier start")
    #timeout = (5.0, 30.0)
    start_time = datetime.datetime.now()

    for i in range(0, 2):
        try:
            email, password = await db.get("user_data_0")
            break
        except KeyError:
            raise MumbleException("Missing database entry from putflag")
    
    print("userdata dauer" , datetime.datetime.now()-start_time)
    for i in range(0, 2):
        try:
            await checker_util_func.login_user(client, logger, email, password)
            break
        except:
            raise MumbleException("Could not login user")
    print("login_user" , datetime.datetime.now()-start_time)
    for i in range(0, 2):
        try:
            await checker_util_func.get_note( client, logger, note = str(task.flag))
            print("get_note" , datetime.datetime.now()-start_time)
            break
        except:
            raise MumbleException("Could not get note")
    end_time = datetime.datetime.now()
    print("getflag hier end")
    print("Time taken getflag 0: ", end_time-start_time)



@checker.exploit(0)
async def exploit_test(
    task: ExploitCheckerTaskMessage,
    db: ChainDB,
    client: AsyncClient,
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    #timeout = (5.0, 30.0)
    if "@example.com" in task.attack_info:
        print("attack_info is good")
    else:
        return None
        #raise MumbleException("attack_info has int")
    start_time = datetime.datetime.now()

    print("attacke hier")
    print(task.attack_info)
    print(task.flag_hash)
    print(task.flag_regex)

    target_email = task.attack_info
    success = True
    for i in range(0, 4):
        try:
            email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
            print(i)
            print("create_user hier")
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
    
    print("public_key hier")
    print(public_key)
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
    print("private_key hier")
    print(private_key)

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
                print(decrypted_message)
                print("flagggg hier")
                if flag := searcher.search_flag(decrypted_message):
                    end_time = datetime.datetime.now()
                    print("Time taken exploit 0: ", end_time-start_time11)
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
    except:
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
    print("havoc hier")
    print("hier 1")
    try:
        email_1, password1_1 = await checker_util_func.create_user(client, logger, public_key='on')
    except:
        raise MumbleException("Could not create user 1 with public key")
    print("hier 2")
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    print("hier 3")
    try:
        await checker_util_func.login_user(client, logger, email_1, password1_1)
    except:
        raise MumbleException("Could not login user")
    print("hier 4")
    try:
        await checker_util_func.logout(client, logger)
    except:
        raise MumbleException("Could not logout")
    print("hier 5")
    try:
        email_2, password1_2 = await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 2 without public key")
    print("hier 6")
    try:
        public_key = await checker_util_func.get_user_of_userlist(client, logger, email = email_1)
    except:
        raise MumbleException("Could not get public key of user 1")
    print("hier 7")
    try:
        await checker_util_func.create_note(client, logger, "havoc", public_key)
    except:
        raise MumbleException("Could not create note with public key")
    print("hier 8")
    try:
        await checker_util_func.get_note(client, logger, note = "havoc")
    except:
        raise MumbleException("Could not get note with public key")
    print("hier 9")
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
    print(redirect_url)
    print("hier re")
    if "login?next=%2Fcreategroup" in group_id:
        print("group_id is bullshit")
        print(group_id)
    
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

    print("1")
    try:
        await checker_util_func.create_user(client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user")
    print("2")
    try:
        await checker_util_func.join_group(client, logger, group_name, group_key, group_id)
    except:
        raise MumbleException("Could not join group")
    print("3")
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
        print("attack_info is good")
    else:
        return None
    print("attacke hier")
    print(task.attack_info)
    print(task.flag_hash)
    print(task.flag_regex)

    target_email = task.attack_info
    try:
        email_attacker, password = await checker_util_func.create_user(client, logger, public_key= None)
    except:
        raise MumbleException("Could not create user 3")
    try:
        response = await checker_util_func.open_group_window(client, logger, task.attack_info)
    except:
        raise MumbleException("Could not open group window")
    
    print("response hier")
    print(response)

    soup_html = BeautifulSoup(response.text, "html.parser")
    li = soup_html.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = [x.strip() for sublist in li for x in sublist]
    li = [x for x in li if x != '']
    
    print("li hier")
    print(li)
    cipher = li[0]
    time = li[2]
    seed = str(int(time.split(":")[0]) + 2) + time.split(":")[1]
    try:
        flag = await checker_util_func.exploit2(client, logger, cipher, str(seed), searcher)
    except:
        raise MumbleException("Could not exploit")
    
    print("flag hier")
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
    try:
        time_str = str(time_db)
        time_calc = time_str.split(':')
        seed = time_calc[0] + time_calc[1]
        print("dies ist der seed",seed)
        random.seed(seed)
        key = random.randint(0, 2**128 - 1).to_bytes(16, byteorder='big')
        nonce = random.randint(0, 2**128 - 1).to_bytes(16, byteorder='big')
        print("dies ist der key",key)
        print("dies ist der nonce",nonce)
    except:
        raise MumbleException("Could not calculate key and nonce")
    
    try:
        #await db.set("group_data_1_noise", (group_name, group_key, group_id, randomNote, time, key, nonce))
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
        group_name, group_key, group_id, randomNote, time = await db.get("group_data_1_noise")
        #group_name, group_key, group_id, randomNote, time, key, nonce = await db.get("group_data_1_noise")
        #print(key)
        #print(nonce)
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
    #     print("response hier 1", response)
    # except:
    #     raise MumbleException("Could not open group window")
    
    # try:
    #     ciphertext = base64.b64decode(ciphertext)
    #     print("das hier sind die notes1") 
    #     cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    #     print("das hier sind die notes2")
    #     padded_plaintext = cipher.decrypt(ciphertext)
    #     print("das hier sind die notes3")
    #     plaintext = unpad(padded_plaintext, AES.block_size)
    #     print("das hier sind die notes4")
    #     print(plaintext)
    #     print(randomNote)
    #     print("das hier sind die notes5")
    #     if plaintext != randomNote.encode():
    #         raise MumbleException("Decryption failed")
    # except:
    #     raise MumbleException("Could not decrypt note")
    
if __name__ == "__main__":
    checker.run()