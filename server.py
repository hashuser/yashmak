import asyncio
import socket
import ssl
import json
import os
import sys
import ipaddress
import time
import traceback
import objgraph

class core():
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=('::', self.config['listen']), family=socket.AF_INET6,
                                            dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=('0.0.0.0', self.config['listen']), family=socket.AF_INET,
                                            dualstack_ipv6=False)
        server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=1024,ssl=self.get_context())
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(server)
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.logging())
        self.loop.run_forever()

    async def logging(self):
        while True:
            file = open('logging.txt', 'a+')
            file.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+'\n')
            for x in objgraph.most_common_types(10):
                file.write(x[0]+':'+str(x[1])+'\n')
            file.write('---------------------------------\n')
            file.close()
            await asyncio.sleep(60)

    async def handler(self, client_reader, client_writer):
        try:
            server_writer = None
            tasks = None
            uuid = await asyncio.wait_for(client_reader.read(36),20)
            if uuid not in self.config['uuid']:
                client_writer.write(b'''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\r\n<html>\r\n<head><title>400Bad Request</title></head>\r\n<body bgcolor="white">\r\n<h1>400 Bad Request</h1>\r\n<p>Your browser sent a request that this server could not understand.<hr/>Powered by Tengine</body>\r\n</html>\r\n''')
                await client_writer.drain()
                raise Exception
            data = 0
            while data == 0:
                data = int.from_bytes((await asyncio.wait_for(client_reader.readexactly(2),20)), 'big',signed=True)
                if data > 0:
                    data = await asyncio.wait_for(client_reader.readexactly(data),20)
                    host, port = self.process(data)
                    address = (await self.loop.getaddrinfo(host=host, port=port, family=0, type=socket.SOCK_STREAM))[0][4]
                    self.is_china_ip(address[0], host, uuid)
                    server_reader, server_writer = await asyncio.open_connection(host=address[0], port=address[1])
                    await asyncio.gather(self.switch(client_reader, server_writer, client_writer),
                                         self.switch(server_reader, client_writer, server_writer))
                elif data == -1:
                    await self.updater(client_writer, uuid)
        except Exception as e:
            traceback.clear_frames(e.__traceback__)
            e.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    async def switch(self, reader, writer, other):
        try:
            while True:
                data = await reader.read(16384)
                writer.write(data)
                await writer.drain()
                if data == b'':
                    break
        except Exception as e:
            traceback.clear_frames(e.__traceback__)
            e.__traceback__ = None
            await self.clean_up(writer, other)
        finally:
            await self.clean_up(writer, other)

    async def updater(self, writer, uuid):
        try:
            if os.path.exists(self.local_path + '/' + uuid.decode('utf-8') + '.txt'):
                file = open(self.local_path + '/' + uuid.decode('utf-8') + '.txt', 'rb')
                content = file.read()
                file.close()
                writer.write(content)
                await writer.drain()
            else:
                writer.write(b'\n')
                await writer.drain()
            await self.clean_up(writer, file)
        except Exception as e:
            traceback.clear_frames(e.__traceback__)
            e.__traceback__ = None
            await self.clean_up(writer, file)

    async def clean_up(self, writer1=None, writer2=None):
        try:
            writer1.close()
            await writer1.wait_closed()
        except Exception as e:
            traceback.clear_frames(e.__traceback__)
            e.__traceback__ = None
        try:
            writer2.close()
            await writer2.wait_closed()
        except Exception as e:
            traceback.clear_frames(e.__traceback__)
            e.__traceback__ = None

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

    def is_china_ip(self,ip ,host, uuid):
        for x in [b'foreign',uuid]:
            if host in self.host_list[x]:
                return False
            sigment_length = len(host)
            while True:
                sigment_length = host.rfind(b'.', 0, sigment_length) - 1
                if sigment_length <= -1:
                    break
                if host[sigment_length + 1:] in self.host_list[x]:
                    return False
        ip = ip.replace('::ffff:','',1)
        ip = int(ipaddress.ip_address(ip))
        for x in self.geoip_list:
            if x[0] < ip and ip < x[1]:
                self.add_host(self.conclude(host), uuid)
                return True
        self.add_host(self.conclude(host), b'foreign')
        return False

    def add_host(self, host, uuid):
        if uuid in self.host_list:
            self.host_list[uuid].add(host.replace(b'*',b''))
        else:
            self.host_list[uuid] = set(host.replace(b'*',b''))

    async def write_host(self):
        def encode(host):
            if host[0] == 46:
                return '*' + host.decode('utf-8')
            return host.decode('utf-8')
        while True:
            for x in self.host_list:
                file = open(self.local_path + '/' + x.decode('utf-8') + '.txt', 'w')
                json.dump(list(map(encode,list(self.host_list[x]))), file)
                file.close()
            await asyncio.sleep(60)

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
        self.host_list = dict()
        self.geoip_list = []
        self.load_config()
        self.load_lists()

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

    def load_lists(self):
        file = open(self.config['geoip'], 'r')
        data = json.load(file)
        file.close()
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()
        self.exception_list_name = self.config['uuid']
        self.exception_list_name.add(b'foreign')
        for x in self.exception_list_name:
            self.host_list[x] = set()
            if os.path.exists(self.local_path + '/' + x.decode('utf-8') + '.txt'):
                file = open(self.local_path + '/' + x.decode('utf-8') + '.txt', 'r')
                data = json.load(file)
                file.close()
                data = list(map(self.encode, data))
                for y in data:
                    self.host_list[x].add(y.replace(b'*', b''))

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')


if __name__ == '__main__':
    server = yashmak()
    server.serve_forever()