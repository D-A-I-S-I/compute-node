import asyncio
import nats
import json

from dataclasses import asdict, dataclass

from nats.errors import ConnectionClosedError, TimeoutError, NoServersError
@dataclass
class Payload:
    id: int
    module: str
    data: str


async def main():
    # It is very likely that the demo server will see traffic from clients other than yours.
    # To avoid this, start your own locally and modify the example to use it.
    nc = await nats.connect("nats://daisi-broker:4222")

    sub = await nc.subscribe("updates", max_msgs=2)
    while(True):
        async for message in sub.messages:
            try:
                payload = Payload(**json.loads(message.data))
                print(f"received valid JSON payload: {payload.id=} {payload.module=} {payload.data=}")
            except json.decoder.JSONDecodeError:
                print(f"received invalid JSON payload: {message.data=}")




if __name__ == "__main__":
    asyncio.run(main())