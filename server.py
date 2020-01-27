import asyncio
import socket
import ssl
import gc
import json
import os
import sys


class core():
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=('::', self.config['listen']), family=socket.AF_INET6,
                                            dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=('0.0.0.0', self.config['listen']), family=socket.AF_INET,
                                            dualstack_ipv6=False)
        server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=1024, loop=self.loop,
                                      ssl=self.get_context())
        self.counter = 0
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(server)
        self.loop.run_forever()

    async def handler(self, client_reader, client_writer):
        try:
            data = await client_reader.read(36)
            if data not in self.config['uuid']:
                client_writer.close()
                raise Exception
            data = await client_reader.read(2)
            data = await client_reader.read(int.from_bytes(data, 'big'))
            host, port = self.process(data)
            server_reader, server_writer = await asyncio.open_connection(host=host, port=port)
            await asyncio.gather(self.switch(client_reader, server_writer, client_writer),
                                 self.switch(server_reader, client_writer, server_writer), loop=self.loop)
        except Exception:
            try:
                client_writer.close()
            except Exception:
                pass
            try:
                server_writer.close()
            except Exception:
                pass
        finally:
            self.counter += 1
            if self.counter > 200:
                gc.collect()
                self.counter = 0

    async def switch(self, reader, writer, other):
        try:
            while True:
                data = await reader.read(16384)
                writer.write(data)
                await writer.drain()
                if data == b'':
                    break
            writer.close()
            other.close()
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            try:
                other.close()
            except Exception:
                pass

    def exception_handler(self, loop, context):
        pass

    def process(self, data):
        return self.get_address(data)

    def get_address(self, data):
        position = data.find(b'\n')
        host = data[:position]
        position += 1
        port = data[position:data.find(b'\n', position)]
        return host, port

    def get_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context


class yashmak(core):
    def __init__(self):
        self.load_config()

    def serve_forever(self):
        core.__init__(self)

    def load_config(self):
        config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/config.json'
        if os.path.exists(config_path):
            file = open(config_path, 'r')
            content = file.read()
            file.close()
            content = self.translate(content)
            self.config = json.loads(content)
            self.config['uuid'] = set(list(map(self.encode, self.config['uuid'])))
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'cert': '', 'key': '', 'uuid': [''], 'listen': ''}
            file = open(config_path, 'w')
            json.dump(example, file, indent=4)
            file.close()

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')


if __name__ == '__main__':
    server = yashmak()
    server.serve_forever()