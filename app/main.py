import asyncio
import json
import os
from dataclasses import asdict, dataclass
import subprocess
import nats
from nats.errors import ConnectionClosedError, NoServersError, TimeoutError
import shlex
import modules

@dataclass
class Payload:
    id: int
    module: str
    data: str


class Compute:
    @classmethod
    async def create(cls):
        self = cls()
        self.modules = {}
        self.nats_url = os.getenv("BROKER_URL", "nats://localhost:4222")
        self.nc = await nats.connect(self.nats_url)
        print(f"Connected to {self.nats_url}")
        self.load_modules()
        return self

    def load_modules(self):
        for module in modules.__all__:
            try:
                c = getattr(modules, module)()
                if hasattr(c, 'module_name'):
                    self.modules[c.module_name] = c
                else:
                    print(f"Loaded module '{module}' does not have a 'module_name' attribute")
            except AttributeError as e:
                print(f"Attribute error loading module '{module}': {e}")
            except Exception as e:
                print(f"Error loading module '{module}': {e}")
            print(f"Loaded module: {module}")

    def transform(self):
        command = "python3 app/json2pcap.py -i ./sample.json -o ./converted.pcap"
        formatted_command = shlex.split(command)
        subprocess.run(formatted_command)

    async def receive(self):
        print("Receiving")
        sub = await self.nc.subscribe("updates")
        while (True):
            async for message in sub.messages:
                try:
                    payload = Payload(**json.loads(message.data))
                    print(
                        f"received valid JSON payload: {payload.id=} {payload.module=} {payload.data=}"
                    )
                    try:
                        self.modules[payload.module].write_to_buffer(payload.data)
                    except KeyError:
                        print(f"Module {payload.module} not found")
                except json.decoder.JSONDecodeError:
                    print(f"received invalid JSON payload: {message.data=}")

    async def run(self):
        print("Running")
        asyncio.gather(*[module.run() for module in self.modules.values()])
        await self.receive()
        await self.nc.drain()

async def main():
    compute = await Compute.create()
    await compute.run()


if __name__ == "__main__":
    asyncio.run(main())
