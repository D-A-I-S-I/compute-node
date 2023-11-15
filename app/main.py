import asyncio
import json
import os
from dataclasses import asdict, dataclass

import nats
from nats.errors import ConnectionClosedError, NoServersError, TimeoutError


@dataclass
class Payload:
    id: int
    module: str
    data: str


class Compute:
    @classmethod
    async def create(cls):
        self = cls()
        self.modules = []
        self.nats_url = os.getenv("BROKER_URL", "nats://localhost:4222")
        self.nc = await nats.connect(self.nats_url)
        return self

    async def receive(self):
        sub = await self.nc.subscribe("updates")
        while (True):
            async for message in sub.messages:
                try:
                    payload = Payload(**json.loads(message.data))
                    print(
                        f"received valid JSON payload: {payload.id=} {payload.module=} {payload.data=}")
                except json.decoder.JSONDecodeError:
                    print(f"received invalid JSON payload: {message.data=}")


async def main():
    compute = await Compute.create()
    await compute.receive()


if __name__ == "__main__":
    asyncio.run(main())
