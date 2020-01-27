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
        server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=1024, loop=self.loop)
        self.context = self.get_context()
        self.counter = 0
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(server)
        self.loop.run_forever()

    async def handler(self, client_reader, client_writer):
        try:
            data = await client_reader.read(65535)
            if data == b'':
                raise Exception
            data, host, port, request_type = self.process(data) 
            if self.config['mode'] == 'global' or (self.config['mode'] == 'auto' and not self.get_exception(host)):
                server_reader, server_writer = await asyncio.open_connection(host=self.config['host'],
                                                                             port=self.config['port'],
                                                                             ssl=self.context,
                                                                             server_hostname=self.config['host'])
                server_writer.write(self.config['uuid'])
                await server_writer.drain()
                server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big'))
                await server_writer.drain()
                server_writer.write(host + b'\n' + port + b'\n')
                await server_writer.drain()
            else:
                server_reader, server_writer = await asyncio.open_connection(host=host, port=port)
            if not request_type:
                client_writer.write(b'''HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n''')
                await client_writer.drain()
            else:
                server_writer.write(data)
                await server_writer.drain()
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
        request_type = self.get_request_type(data)
        host, port = self.get_address(data, request_type)
        data = self.get_response(data, request_type, host, port)
        return data, host, port, request_type

    def get_request_type(self, data):
        if data[:7] == b'CONNECT':
            request_type = 0
        elif data[:3] == b'GET':
            request_type = 1
        elif data[:4] == b'POST':
            request_type = 2
        return request_type

    def get_address(self, data, request_type):
        position = data.find(b' ') + 1
        sigment = data[position:data.find(b' ', position)]
        if request_type:
            position = sigment.find(b'//') + 2
            sigment = sigment[position:sigment.find(b'/', position)]
        position = sigment.rfind(b':')
        if position > 0 and position > sigment.rfind(b']'):
            host = sigment[:position]
            port = sigment[position + 1:]
        else:
            host = sigment
            port = b'80'
        host = host.replace(b'[', b'', 1)
        host = host.replace(b']', b'', 1)
        return host, port

    def get_response(self, data, request_type, host, port):
        if request_type:
            data = data.replace(b'http://', b'', 1)
            data = data.replace(host, b'', 1)
            data = data.replace(b':' + port, b'', 1)
            data = data.replace(b'Proxy-', b'', 1)
        return data

    def get_exception(self, host):
        if host in self.exception_list:
            return True
        sigment_length = len(host)
        while True:
            sigment_length = host.rfind(b'.', 0, sigment_length) - 1
            if sigment_length <= -1:
                break
            if host[sigment_length + 1:] in self.exception_list:
                return True
        return False

    def get_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config['cert'])
        return context


class yashmak(core):
    def __init__(self):
        self.exception_list = set()
        self.load_config()
        self.load_exception_list()

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
            self.config[self.config['active']]['mode'] = self.config['mode']
            self.config[self.config['active']]['china_list'] = self.config['china_list']
            self.config = self.config[self.config['active']]
            self.config['uuid'] = self.config['uuid'].encode('utf-8')
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'mode': '', 'active': '', 'china_list': '',
                       'server01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}
            file = open(config_path, 'w')
            json.dump(example, file, indent=4)
            file.close()

    def load_exception_list(self):
        if self.config['china_list'] != '':
            file = open(self.config['china_list'], 'r')
            data = json.load(file)
            file.close()
            data = list(map(self.encode,data))
            for x in data:
                self.exception_list.add(x.replace(b'*',b''))

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')


if __name__ == '__main__':
    server = yashmak()
    server.serve_forever()