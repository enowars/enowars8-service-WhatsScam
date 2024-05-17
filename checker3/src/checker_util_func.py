from asyncio import StreamReader, StreamWriter
import asyncio
import random
import string
#import faker


from httpx import AsyncClient
from typing import Optional
from logging import LoggerAdapter
from bs4 import BeautifulSoup


import checker_util_func




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
    logger.info(f"Server answered: {response.status_code} - {response.text}")

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

    response = await client.get("/logout", follow_redirects=True)
    logger.info(f"Server answered: {response.status_code} - {response.text}")

    assert_equals(100 < response.status_code < 300, True, "Logging out failed")

async def get_user_of_userlist(
    db: ChainDB,
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
    #print(public_key[0].strip())
    

    return public_key[0].strip()