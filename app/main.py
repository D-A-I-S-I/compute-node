from nats.errors import ConnectionClosedError, NoServersError, TimeoutError
from dataclasses import asdict, dataclass

import subprocess
import logging
import modules
import asyncio
import shlex
import json
import nats
import os
import pickle


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
                c = getattr(modules, module)(self.handle_alert)
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
                    module = message.headers['module_name']
                    data = pickle.loads(message.data)
                    logging.log(logging.INFO, f'Received message: {module}: {data}')
                    try:
                        self.modules[module].write_to_buffer(data)
                    except KeyError:
                        logging.log(logging.ERROR, f"Module {module} not found")
                    except Exception as e:
                        logging.log(logging.ERROR, f"Error writing to module buffer: {e}")
                except json.decoder.JSONDecodeError:
                    logging.log(logging.ERROR, f"received invalid JSON payload: {message.data=}")
                except Exception as e:
                    logging.log(logging.ERROR, f"Error receiving message: {e}")

    async def run(self):
        print("Running")
        asyncio.gather(*[module.run() for module in self.modules.values()])
        await self.receive()
        await self.nc.drain()

    def handle_alert(self, module_name, alert, data=None):
        logging.log(logging.CRITICAL, f"Alert from {module_name}: {alert}")
        if data: print(f"Alert data: {data=}")

async def main():
    compute = await Compute.create()
    await compute.run()


if __name__ == "__main__":
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper() # LOG_LEVEL=INFO make ... for more verbose logging.
    logging.basicConfig(level=log_level)
    asyncio.run(main())
