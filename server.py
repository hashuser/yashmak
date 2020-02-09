import asyncio
import socket
import ssl
import gc
import json
import os
import sys
import ipaddress


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
            uuid = data
            data = int.from_bytes((await client_reader.read(2)), 'big', signed=True)
            if data > 0:
                data = await client_reader.read(data)
                host, port = self.process(data)
                address = (await self.loop.getaddrinfo(host=host, port=port, family=0, type=socket.SOCK_STREAM))[0][4]
                if self.get_exception(address[0], host):
                    self.add_host(host, uuid)
                server_reader, server_writer = await asyncio.open_connection(host=address[0], port=address[1])
                await asyncio.gather(self.switch(client_reader, server_writer, client_writer),
                                     self.switch(server_reader, client_writer, server_writer), loop=self.loop)
            else:
                await self.updater(client_writer, uuid)
        except Exception:
            self.clean_up(client_writer, server_writer)
        finally:
            self.get_gc()

    async def switch(self, reader, writer, other):
        try:
            while True:
                data = await reader.read(16384)
                writer.write(data)
                await writer.drain()
                if data == b'':
                    break
            self.clean_up(writer, other)
        except Exception:
            self.clean_up(writer, other)

    async def updater(self, writer, uuid):
        try:
            file = None
            if os.path.exists(self.local_path + '/' + uuid.decode('utf-8') + '.txt'):
                file = open(self.local_path + '/' + uuid.decode('utf-8') + '.txt', 'rb')
                content = file.read()
                file.close()
                writer.write(content)
                await writer.drain()
            else:
                writer.write(b'\n')
                await writer.drain()
            self.clean_up(writer, file)
        except Exception:
            self.clean_up(writer, file)

    def clean_up(self, writer1, writer2):
        try:
            writer1.close()
        except Exception:
            pass
        try:
            writer2.close()
        except Exception:
            pass

    def get_gc(self):
        self.counter += 1
        if self.counter > 200:
            gc.collect()
            self.counter = 0

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

    def get_exception(self,ip ,host):
        if host in self.common:
            return False
        sigment_length = len(host)
        while True:
            sigment_length = host.rfind(b'.', 0, sigment_length) - 1
            if sigment_length <= -1:
                break
            if host[sigment_length + 1:] in self.common:
                return False
        ip = ip.replace('::ffff:','',1)
        ip = int(ipaddress.ip_address(ip))
        for x in self.exception_list:
            if x[0] < ip and ip < x[1]:
                self.common.add(self.conclude(host).replace(b'*', b''))
                return True
        self.common.add(self.conclude(host).replace(b'*', b''))
        self.add_host(self.conclude(host), b'common')
        return False

    def add_host(self, host, uuid):
        data = []
        if os.path.exists(self.local_path + '/' + uuid.decode('utf-8') + '.txt'):
            file = open(self.local_path + '/' + uuid.decode('utf-8') + '.txt', 'r')
            data = json.load(file)
            file.close()
        data.append(self.conclude(host).decode('utf-8'))
        data = list(set(data))
        file = open(self.local_path + '/' + uuid.decode('utf-8') + '.txt', 'w')
        json.dump(data, file)
        file.close()

    def conclude(self, data):
        def detect(data):
            if data.count(b':') != 0 or data.count(b'.') <= 1:
                return False
            SLD = {b'com', b'net', b'org', b'gov',
                   b'co', b'edu', b'uk', b'us', b'kr',
                   b'au', b'hk', b'is', b'jpn', b'gb', b'gr'}
            if data.split(b'.')[-2] in SLD and data.count(b'.') < 3:
                return False
            for x in data:
                if x < 48 and x != 46 or x > 57:
                    return True
            return False

        if detect(data):
            return b'*' + data[data.find(b'.'):]
        else:
            return data

    def get_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context


class yashmak(core):
    def __init__(self):
        self.common = set()
        self.exception_list = []
        self.load_config()
        self.load_exception_list()

    def serve_forever(self):
        core.__init__(self)

    def load_config(self):
        self.local_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        if os.path.exists(self.local_path + '/config.json'):
            file = open(self.local_path + '/config.json', 'r')
            content = file.read()
            file.close()
            content = self.translate(content)
            self.config = json.loads(content)
            self.config['uuid'] = set(list(map(self.encode, self.config['uuid'])))
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'geoip': '','cert': '', 'key': '', 'uuid': [''], 'listen': ''}
            file = open(self.local_path + '/config.json', 'w')
            json.dump(example, file, indent=4)
            file.close()

    def load_exception_list(self):
        file = open(self.config['geoip'], 'r')
        data = json.load(file)
        file.close()
        for x in data:
            network = ipaddress.ip_network(x)
            self.exception_list.append([int(network[0]),int(network[-1])])
        self.exception_list.sort()
        file = open(self.local_path + '/common.txt', 'r')
        data = json.load(file)
        file.close()
        data = list(map(self.encode, data))
        for x in data:
            self.common.add(x.replace(b'*', b''))
        for x in self.config['uuid']:
            if os.path.exists(self.local_path + '/' + x.decode('utf-8')):
                file = open(self.local_path + '/' + x.decode('utf-8'), 'r')
                data = json.load(file)
                file.close()
                data = list(map(self.encode, data))
                for y in data:
                    self.common.add(y.replace(b'*', b''))

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')


if __name__ == '__main__':
    server = yashmak()
    server.serve_forever()