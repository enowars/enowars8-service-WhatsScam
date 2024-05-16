import secrets
from typing import Optional

from httpx import AsyncClient

from enochecker3 import (
    ChainDB,
    Enochecker,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in


checker = Enochecker("whatsscam", 5050)
def app(): return checker.app

@checker.putflag(0)
async def putflag_test(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    print("hey")

@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    print("hey")
    



if __name__ == "__main__":
    checker.run()