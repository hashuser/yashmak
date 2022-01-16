from PyQt5 import QtWidgets, QtGui, QtCore
from dns import message
import base64
import asyncio
import socket
import ssl
import json
import os
import sys
import ipaddress
import traceback
import gzip
import time
import datetime
import multiprocessing
import ctypes
import winreg
import random
import win32api
import gc
import psutil

gc.set_threshold(100000, 50, 50)

class yashmak_core():
    def __init__(self):
        try:
            self.init()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self):
        self.proxy_context = self.get_proxy_context()
        self.normal_context = self.get_normal_context()
        self.connection_pool = []
        self.connection_count = 0
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.ipv4 = True
        self.ipv6 = True
        self.is_updating = True
        self.main_port_fail = 0
        self.backup(self.config['white_list'], 'old.json')
        self.set_priority()
        self.create_loop()

    def create_server(self):
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=('::', self.config['listen']), family=socket.AF_INET6,
                                            dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=('0.0.0.0', self.config['listen']), family=socket.AF_INET,
                                            dualstack_ipv6=False)
        return asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048)

    def create_loop(self):
        self.loop = asyncio.get_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        # self.loop.create_task(self.TCP_ping())
        self.loop.create_task(self.pool())
        self.loop.create_task(self.pool_health())
        self.loop.create_task(self.white_list_updater())
        self.loop.create_task(self.yashmak_updater())
        self.loop.create_task(self.clear_cache())
        self.loop.create_task(self.check_parent())
        self.loop.create_task(self.ipv4_test())
        self.loop.create_task(self.ipv6_test())
        self.loop.run_forever()

    def set_priority(self):
        p = psutil.Process(os.getpid())
        p.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS)

    async def handler(self, client_reader, client_writer):
        try:
            server_writer = None
            tasks = None
            data = await asyncio.wait_for(client_reader.read(65535),20)
            if data == b'':
                raise Exception
            data, URL, host, port, request_type = await self.process(data, client_reader, client_writer)
            await self.redirect(client_writer,host,URL)
            server_reader, server_writer = await self.proxy(host,port,request_type,data,client_writer,self.get_type(host))
            await asyncio.gather(self.switch(client_reader, server_writer, client_writer, True),
                                 self.switch(server_reader, client_writer, server_writer, False))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    async def switch(self, reader, writer, other, up):
        try:
            if not up:
                while 1:
                    data = await reader.read(16384)
                    if data == b'':
                        raise Exception
                    writer.write(data)
                    await writer.drain()
            else:
                while 1:
                    data = await reader.read(65536)
                    if data == b'':
                        raise Exception
                    instruction = data[:4]
                    if b'GET' in instruction or b'POST' in instruction:
                        URL, host, port = self.get_http_address_new(data, 1, False)
                        data = self.get_response(data, host, port)
                    writer.write(data)
                    await writer.drain()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer, other)

    async def redirect(self, writer, host, URL):
        try:
            def HSTS(HSTS_list,host):
                if host in HSTS_list:
                    return True
                sigment_length = len(host)
                while 1:
                    sigment_length = host.rfind(b'.', 0, sigment_length) - 1
                    if sigment_length <= -1:
                        break
                    if host[sigment_length + 1:] in HSTS_list:
                        return True

            if URL != None and HSTS(self.HSTS_list,host):
                await self.http_response(writer, 301, URL)
                await self.clean_up(writer)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            raise Exception(error)

    async def proxy(self, host, port, request_type, data, client_writer, type):
        server_writer = None
        try:
            server_reader, server_writer = await self.make_proxy(host,port,data,request_type,type,client_writer)
            return server_reader, server_writer
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            raise Exception(error)

    async def make_proxy(self,host,port,data,request_type,type,client_writer):
        IPs = await self.get_IPs(type,host,client_writer)
        IPs_length = len(IPs)
        for x in range(IPs_length):
            address = IPs[int(random.random() * 1000 % IPs_length)]
            if type or (self.config['mode'] == 'auto' and not self.is_china_ip(address)):
                server_reader, server_writer = await self.do_handshake(host, port)
            elif address != '127.0.0.1':
                try:
                    server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port), 5)
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
                    continue
            elif not request_type:
                await self.http_response(client_writer, 404)
                raise Exception
            if not request_type:
                await self.http_response(client_writer, 200)
            elif data != None:
                server_writer.write(data)
                await server_writer.drain()
            break
        return server_reader, server_writer

    async def get_IPs(self,type,host,client_writer):
        if not type:
            if self.ipv4 and self.ipv6:
                IPs = await self.resolve('ALL', host)
            elif self.ipv4:
                IPs = await self.resolve('A', host)
            elif self.ipv6:
                IPs = await self.resolve('AAAA', host)
            else:
                await self.http_response(client_writer, 502)
                raise Exception('No IP Error')
            if IPs == None:
                await self.http_response(client_writer, 502)
                raise Exception
        else:
            IPs = [None]
        return IPs

    async def do_handshake(self,host,port):
        if len(self.connection_pool) == 0:
            server_reader, server_writer = await self.connect_proxy_server()
            self.is_updating = False
            server_writer.write(self.config['uuid'])
            await server_writer.drain()
        else:
            server_reader, server_writer = self.connection_pool.pop(-1)
        server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big', signed=True))
        await server_writer.drain()
        server_writer.write(host + b'\n' + port + b'\n')
        await server_writer.drain()
        return server_reader, server_writer

    async def http_response(self,writer,type,URL=None):
        if type == 200:
            writer.write(b'''HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n''')
        elif type == 301:
            writer.write(b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\nConnection: close\r\n\r\n''')
        elif type == 404:
            writer.write(b'''HTTP/1.1 404 Not Found\r\nProxy-Connection: close\r\n\r\n''')
        elif type == 502:
            writer.write(b'''HTTP/1.1 502 Bad Gateway\r\nProxy-Connection: close\r\n\r\n''')
        else:
            raise Exception('Unknown Status Code')
        await writer.drain()

    async def clean_up(self, writer1=None, writer2=None):
        try:
            if writer1 != None:
                writer1.close()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                writer2.close()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer1 != None:
                await writer1.wait_closed()
                writer1 = None
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                await writer2.wait_closed()
                writer2 = None
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def pool(self):
        self.pool_max_size = 16
        self.is_checking = 0
        self.is_connecting = 0
        if self.config['mode'] == 'direct':
            return 0
        while 1:
            for x in range(self.pool_max_size-(len(self.connection_pool) + self.is_checking + self.is_connecting)):
                try:
                    self.loop.create_task(self.make_connections())
                    self.is_connecting += 1
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
            await asyncio.sleep(0.5)

    async def make_connections(self):
        try:
            server_reader, server_writer = await self.connect_proxy_server()
            self.is_updating = False
            server_writer.write(self.config['uuid'])
            await server_writer.drain()
            self.connection_pool.append((server_reader, server_writer))
            self.is_connecting -= 1
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            self.is_connecting -= 1

    async def connect_proxy_server(self):
        server_reader, server_writer = None, None
        if self.main_port_fail <= 100:
            ports = [self.config['port'], self.get_calculated_port()]
        else:
            ports = [self.get_calculated_port()]
        for x in ports:
            try:
                server_reader, server_writer = await asyncio.open_connection(host=self.config['host'],
                                                                             port=x,
                                                                             ssl=self.proxy_context,
                                                                             server_hostname=self.config['host'],
                                                                             ssl_handshake_timeout=5)
                return server_reader, server_writer
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                if x == self.config['port'] and (await self.has_internet()):
                    self.main_port_fail += 1
        if server_reader == None or server_writer == None:
            self.update_yashmak()
            raise Exception(error)

    async def pool_health(self):
        self.slow_mode = True
        self.unhealthy = 0
        if self.config['mode'] == 'direct':
            return 0
        while 1:
            try:
                for x in list(self.connection_pool):
                    try:
                        self.connection_pool.remove(x)
                        self.is_checking += 1
                        self.loop.create_task(self.check_health(x))
                        if self.slow_mode and self.unhealthy < ((len(self.connection_pool)+self.is_checking)*0.05 + 4):
                            await asyncio.sleep(0.1)
                    except Exception as error:
                        traceback.clear_frames(error.__traceback__)
                        error.__traceback__ = None
                self.slow_mode = True
                self.unhealthy = 0
                await self.sleep()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def sleep(self):
        for x in range(10):
            S = time.time()
            await asyncio.sleep(0.5)
            E = time.time()
            if E - S > 1.5:
                self.slow_mode = False
                break

    async def check_health(self, x):
        try:
            x[1].write(int.to_bytes(-4, 2, 'big', signed=True))
            await x[1].drain()
            if (await asyncio.wait_for(x[0].read(1024),5)) == b'':
                raise Exception
            self.connection_pool.append(x)
            self.is_checking -= 1
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            self.is_checking -= 1
            self.unhealthy += 1
            await self.clean_up(x[0], x[1])

    async def network_detector_worker(self,address):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            await self.loop.sock_connect(s, address)
            await self.clean_up(s, None)
            return 1
        except Exception:
            await self.clean_up(s, None)
            return 0

    async def has_internet(self):
        DNS_IPs = ['114.114.114.114', '223.5.5.5', '119.29.29.29', '180.76.76.76', '1.2.4.8', '8.8.8.8', '1.1.1.1']
        tasks = []
        status = False
        for x in DNS_IPs:
            tasks.append(asyncio.create_task(self.network_detector_worker((x, 53))))
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for x in done:
            status += x.result()
        for x in pending:
            x.cancel()
        if status:
            return True
        return False

    async def yashmak_updater(self):
        S = time.time()
        while 1:
            if time.time() - S > 7200:
                self.update_yashmak()
                S = time.time()
            await asyncio.sleep(300)

    def update_yashmak(self):
        try:
            if not os.path.exists(self.config_path + 'download.json') and not self.is_updating:
                win32api.ShellExecute(0, 'open', r'Downloader.exe', '', '', 1)
                self.is_updating = True
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def white_list_updater(self):
        while 1:
            try:
                server_writer = None
                file = None
                server_reader, server_writer = await self.connect_proxy_server()
                server_writer.write(self.config['uuid'])
                await server_writer.drain()
                server_writer.write(int.to_bytes(-3, 2, 'big', signed=True))
                await server_writer.drain()
                customize = b''
                while 1:
                    data = await server_reader.read(8192)
                    if data == b'' or data == b'\n':
                        break
                    customize += data
                if os.path.exists(self.config['white_list']) and customize != b'':
                    with open(self.config['white_list'], 'r') as file:
                        data = json.load(file)
                    customize = json.loads(gzip.decompress(customize))
                    data += customize
                    for x in list(map(self.encode, customize)):
                        self.white_list.add(x.replace(b'*', b''))
                    data = list(set(data))
                    self.backup(self.config['white_list'],'chinalist.json')
                    await asyncio.sleep(1)
                    with open(self.config['white_list'], 'w') as file:
                        json.dump(data, file)
                elif customize != b'':
                    self.backup(self.config['white_list'],'chinalist.json')
                    await asyncio.sleep(1)
                    with open(self.config['white_list'], 'wb') as file:
                        file.write(customize)
                await self.clean_up(server_writer, file)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer)
            await asyncio.sleep(60)

    def backup(self,path,filename):
        os.makedirs(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup', exist_ok=True)
        with open(path,'rb') as ofile:
            with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup/' + filename, 'wb') as bkfile:
                bkfile.write(ofile.read())

    def exception_handler(self, loop, context):
        pass

    async def process(self, data, client_reader, client_writer):
        request_type = self.get_request_type(data)
        if request_type == 3:
            host, port = await self.get_socks5_address(client_reader, client_writer)
            data = None
            URL = None
        elif request_type == 0:
            URL, host, port = self.get_http_address_new(data, request_type)
            if host == None or port == None:
                URL, host, port = self.get_http_address_old(data, request_type)
            data = None
        else:
            URL, host, port = self.get_http_address_new(data, request_type)
            if host == None or port == None:
                URL, host, port = self.get_http_address_old(data, request_type)
            data = self.get_response(data, host, port)
        return data, URL, host, port, request_type

    def get_type(self, host):
        if self.config['mode'] == 'global':
            return True
        elif self.config['mode'] == 'direct':
            return False
        elif self.config['mode'] == 'auto':
            ip = self.is_ip(host)
            if not ip and self.in_it(host, self.black_list):
                return True
            elif not ip and not self.in_it(host, self.white_list):
                return True
            elif ip and not self.is_china_ip(host):
                return True
        return False

    def get_request_type(self, data):
        if data[:7] == b'CONNECT':
            request_type = 0
        elif data[:3] == b'GET':
            request_type = 1
        elif data[:4] == b'POST':
            request_type = 2
        else:
            request_type = 3
        return request_type

    def get_http_address_new(self, data, request_type, get_url=True):
        host = None
        port = None
        URL = None
        position = data.find(b' ') + 1
        sigment = data[position:data.find(b' ', position)]
        if request_type and get_url:
            URL = sigment.replace(b'http', b'https', 1)
        position = data.find(b'Host: ') + 6
        if position <= 5:
            return None, None, None
        sigment = data[position:data.find(b'\r\n', position)]
        if b':' in sigment:
            port = sigment[sigment.rfind(b':') + 1:]
            host = sigment[:sigment.rfind(b':')]
        elif request_type == 0:
            host = sigment
            port = b'443'
        else:
            host = sigment
            port = b'80'
        return URL, host, port

    def get_http_address_old(self, data, request_type):
        host = None
        port = None
        URL = None
        position = data.find(b' ') + 1
        sigment = data[position:data.find(b' ', position)]
        if request_type:
            URL = sigment.replace(b'http', b'https', 1)
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
        return URL, host, port

    async def get_socks5_address(self, client_reader, client_writer):
        client_writer.write(b'\x05\x00')
        await client_writer.drain()
        data = await asyncio.wait_for(client_reader.read(65535), 20)
        if data[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, data[4:8]).encode('utf-8')
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        elif data[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, data[4:20]).encode('utf-8')
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        elif data[3] == 3:
            host = data[5:5 + data[4]]
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        client_writer.write(b'\x05\x00\x00' + data[3:])
        await client_writer.drain()
        return host, port

    def get_response(self, data, host, port):
        data = data.replace(b'http://', b'', 1)
        data = data[:data.find(b' ')+1]+data[data.find(b'/'):]
        data = data.replace(b'Proxy-', b'', 1)
        return data

    def in_it(self, host, var):
        if host in var:
            return True
        sigment_length = len(host)
        while 1:
            sigment_length = host.rfind(b'.', 0, sigment_length) - 1
            if sigment_length <= -1:
                break
            if host[sigment_length + 1:] in var:
                return True
        return False

    def is_ip(self, host):
        try:
            if b':' in host or int(host[host.rfind(b'.') + 1:]):
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    def is_ipv6(self, ip):
        try:
            if b':' in ip and b'::ffff:' not in ip:
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    def is_china_ip(self, ip):
        ip = ip.replace(b'::ffff:',b'',1)
        ip = int(ipaddress.ip_address(ip.decode('utf-8')))
        left = 0
        right = len(self.geoip_list) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if self.geoip_list[mid][0] <= ip and ip <= self.geoip_list[mid][1]:
                return True
            elif self.geoip_list[mid][1] < ip:
                left = mid + 1
            elif self.geoip_list[mid][0] > ip:
                right = mid - 1
        return False

    def get_proxy_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context

    def get_normal_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context

    async def ipv4_test(self):
        tasks = [('114.114.114.114',53), ('119.29.29.29',53),('ipv4.testipv6.cn',443), ('ipv4.lookup.test-ipv6.com',443),
                 ('ipv4.test-ipv6.hkg.vr.org',443)]
        fail = 0
        for task in tasks:
            try:
                server_writer = None
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=task[0], port=task[1]), 1)
                await self.clean_up(server_writer, None)
                break
            except Exception as error:
                fail += 1
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer, None)
        if fail >= len(tasks):
            self.ipv6 = False

    async def ipv6_test(self):
        tasks = [('2400:3200:baba::1',53), ('2402:4e00::',53), ('ipv6.testipv6.cn',443), ('ipv6.lookup.test-ipv6.com',443),
                 ('ipv6.test-ipv6.hkg.vr.org',443)]
        fail = 0
        for task in tasks:
            try:
                server_writer = None
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=task[0], port=task[1]), 1)
                await self.clean_up(server_writer, None)
                break
            except Exception as error:
                fail += 1
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer, None)
        if fail >= len(tasks):
            self.ipv6 = False

    async def resolve(self,q_type,host,doh=True):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host]
        elif host in self.dns_pool and (time.time() - self.dns_ttl[host]) < 600:
            return self.dns_pool[host][q_type]
        return (await self.query(host,doh))[q_type]

    async def query(self,host,doh):
        ipv4 = None
        ipv6 = None
        for x in range(12):
            ipv4, ipv6 = await asyncio.gather(self.query_worker(host, 'A', doh), self.query_worker(host, 'AAAA', doh))
            if ipv4 != None and ipv6 != None:
                break
            await asyncio.sleep(0.5)
        result = {'A':ipv4,'AAAA':ipv6,'ALL':ipv4+ipv6}
        if ipv4 != None and ipv6 != None:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
        return result

    async def query_worker(self, host, q_type, doh):
        try:
            done, pending, = await asyncio.wait(await self.make_tasks(host, q_type, doh),return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
            result = message.from_wire(done.pop().result())
            return self.decode(str(result), q_type)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def make_tasks(self, host, q_type, doh):
        try:
            if q_type == 'A':
                mq_type = 1
            elif q_type == 'AAAA':
                mq_type = 28
            query = message.make_query(host.decode('utf-8'), mq_type)
            query = query.to_wire()
            tasks = []
            for x in self.config['normal_dns']:
                tasks.append(asyncio.create_task(self.get_normal_query_response(query, (x, 53))))
            if doh:
                for x in self.config['doh_dns']:
                    v4 = await self.resolve('A', x, False)
                    v6 = await self.resolve('AAAA', x, False)
                    if v4 != []:
                        tasks.append(asyncio.create_task(self.get_doh_query_response(query, (v4[0], 443), x)))
                    if v6 != []:
                        tasks.append(asyncio.create_task(self.get_doh_query_response(query, (v6[0], 443), x)))
            return tasks
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def get_normal_query_response(self, query, address):
        try:
            if self.is_ipv6(address[0]):
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            await self.loop.sock_connect(s, (address[0].decode('utf-8'),address[1]))
            await self.loop.sock_sendall(s, query)
            result = await asyncio.wait_for(self.loop.sock_recv(s, 4096),4)
            return result
        except Exception as error:
            await asyncio.sleep(5)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(s, None)
        finally:
            await self.clean_up(s, None)

    async def get_doh_query_response(self, query, address, hostname):
        try:
            server_writer = None
            server_reader, server_writer = await asyncio.open_connection(host=address[0],
                                                                         port=address[1],
                                                                         ssl=self.normal_context,
                                                                         server_hostname=hostname,
                                                                         ssl_handshake_timeout=5)
            server_writer.write(b'GET /dns-query?dns=' + base64.b64encode(query).rstrip(b'=') +b' HTTP/1.1\r\nHost: '+ hostname +b'\r\nContent-type: application/dns-message\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62\r\n\r\n')
            await server_writer.drain()
            result = await asyncio.wait_for(server_reader.read(4096),4)
            result = result[result.find(b'\r\n\r\n')+4:]
            return result
        except Exception as error:
            await asyncio.sleep(5)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer, None)
        finally:
            await self.clean_up(server_writer, None)

    def decode(self,result,type):
        IPs = []
        type = ' ' + type.upper() + ' '
        position = result.find(type)
        if position < 0:
            return []
        while position > 0:
            IPs.append(result[position + len(type):result.find('\n', position)].encode('utf-8'))
            position = result.find(type, position + len(type))
        if result[-1] == '.':
            result = result[:-1]
        return IPs

    async def clear_cache(self):
        while 1:
            try:
                for x in list(self.dns_pool.keys()):
                    if (time.time() - self.dns_ttl[x]) > 600:
                        del self.dns_pool[x]
                        del self.dns_ttl[x]
                for x in range(600):
                    S = time.time()
                    await asyncio.sleep(0.5)
                    E = time.time()
                    if E - S > 1.5:
                        break
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def check_parent(self):
        ppid = os.getppid()
        while 1:
            if ppid not in psutil.pids():
                sys.exit(0)
            await asyncio.sleep(10)

    async def TCP_ping(self):
        try:
            t_t = 0
            t_c = 0
            while 1:
                server_reader, server_writer = await self.connect_proxy_server()
                server_writer.write(self.config['uuid'])
                await server_writer.drain()
                server_writer.write(int.to_bytes(-2, 2, 'big', signed=True))
                await server_writer.drain()
                s_t = time.perf_counter_ns()
                server_writer.write(int.to_bytes(s_t, 8, 'big', signed=True))
                await server_writer.drain()
                await asyncio.wait_for(server_reader.read(8), 20)
                r_t = time.perf_counter_ns()
                t_t += (r_t - s_t) / 1000000
                t_c += 1
                print('This Ping:',round((r_t - s_t) / 1000000, 1), 'ms   Avarage:',round(t_t / t_c, 1),'ms')
                await asyncio.sleep(1)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)
        finally:
            await self.clean_up(server_writer)

    def get_today(self):
        today = int(str(datetime.datetime.utcnow())[:10].replace('-', '')) ** 3
        return int(str(today)[today % 8:8] + str(today)[0:today % 8])

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976


class yashmak(yashmak_core):
    def __init__(self):
        self.white_list = set()
        self.black_list = set()
        self.HSTS_list = set()
        self.geoip_list = []
        self.load_config()
        self.set_proxy()
        self.load_exception_list()
        self.write_pid()
        try:
            win32api.ShellExecute(0, 'open', r'Downloader.exe', '', '', 1)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        yashmak_core.__init__(self)

    def load_config(self):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        if os.path.exists(self.config_path + 'config.json'):
            with open(self.config_path + 'config.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
            self.config[self.config['active']]['startup'] = self.config['startup']
            self.config[self.config['active']]['mode'] = self.config['mode']
            self.config[self.config['active']]['white_list'] = self.config_path + self.config['white_list']
            self.config[self.config['active']]['black_list'] = self.config_path + self.config['black_list']
            self.config[self.config['active']]['HSTS_list'] = self.config_path + self.config['HSTS_list']
            self.config[self.config['active']]['geoip_list'] = self.config_path + self.config['geoip_list']
            self.config[self.config['active']]['normal_dns'] = list(map(self.encode, self.config['normal_dns']))
            self.config[self.config['active']]['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
            self.config = self.config[self.config['active']]
            self.config['uuid'] = self.config['uuid'].encode('utf-8')
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'version': '','startup': '', 'mode': '', 'active': '', 'white_list': '', 'black_list': '', 'HSTS_list': '', 'geoip_list': '',
                       'normal_dns': [''], 'doh_dns': [''], 'server01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}
            with open(self.config_path + 'config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_exception_list(self):
        def load_list(location, var, func):
            if location != '':
                with open(location, 'r') as file:
                    data = json.load(file)
                data = list(map(func, data))
                for x in data:
                    var.add(x.replace(b'*', b''))

        load_list(self.config['white_list'], self.white_list, self.encode)
        load_list(self.config['black_list'], self.black_list, self.encode)
        load_list(self.config['HSTS_list'], self.HSTS_list, self.encode)
        with open(self.config['geoip_list'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()

    def set_proxy(self):
        platform = sys.platform
        if platform == 'win32':
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',0, winreg.KEY_ALL_ACCESS)
            ENVIRONMENT_SETTING = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Environment',0, winreg.KEY_ALL_ACCESS)

            def set_key(root, name, value):
                try:
                    _, reg_type = winreg.QueryValueEx(root, name)
                    winreg.SetValueEx(root, name, 0, reg_type, value)
                except Exception:
                    if type(value) == type("a"):
                        reg_type = 1
                    elif type(value) == type(1):
                        reg_type = 4
                    winreg.SetValueEx(root, name, 0, reg_type, value)

            set_key(INTERNET_SETTINGS, 'ProxyEnable', 1)
            set_key(INTERNET_SETTINGS, 'ProxyOverride', 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;windows10.microdone.cn;<local>')
            set_key(INTERNET_SETTINGS, 'ProxyServer', 'http://127.0.0.1:' + str(self.config['listen']))
            set_key(ENVIRONMENT_SETTING, 'HTTP_PROXY', 'http://127.0.0.1:' + str(self.config['listen']))
            set_key(ENVIRONMENT_SETTING, 'HTTPS_PROXY', 'http://127.0.0.1:' + str(self.config['listen']))
            internet_set_option = ctypes.windll.wininet.InternetSetOptionW
            internet_set_option(0, 37, 0, 0)
            internet_set_option(0, 39, 0, 0)
        elif platform == 'darwin':
            os.popen('''networksetup -setwebproxystate "Wi-Fi" on''')
            os.popen('''networksetup -setsecurewebproxystate "Wi-Fi" on''')
            os.popen('''networksetup -setwebproxy "Wi-Fi" 127.0.0.1 '''+str(self.config['listen']))
            os.popen('''networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 '''+str(self.config['listen']))
            os.popen('''networksetup -setproxybypassdomains "Wi-Fi" localhost 127.* 10.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 172.32.* 192.168.*''')
            os.popen('''networksetup -setwebproxystate "Ethernet" on''')
            os.popen('''networksetup -setsecurewebproxystate "Ethernet" on''')
            os.popen('''networksetup -setwebproxy "Ethernet" 127.0.0.1 '''+str(self.config['listen']))
            os.popen('''networksetup -setsecurewebproxy "Ethernet" 127.0.0.1 '''+str(self.config['listen']))
            os.popen('''networksetup -setproxybypassdomains "Ethernet" localhost 127.* 10.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 172.32.* 192.168.*''')

    def write_pid(self):
        with open(self.config_path + 'pid','w') as file:
            file.write(str(os.getpid()))

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')

class windows(QtWidgets.QMainWindow):
    def __init__(self):
        super(windows, self).__init__()
        self.init_windows()

    def activate(self,reason):
        if reason == 1:
            position = win32api.GetCursorPos()
            self.tpmen.popup(QtCore.QPoint(position[0], position[1]))

    def close_menu(self):
        self.tpmen.close()
        self.timer.stop()

    def init_windows(self):
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.enable_loopback_UWPs()
                sys.exit(0)
            self.run()
            self.language = self.detect_language()[0]
            self.actions = {
                'Auto': QtWidgets.QAction(self.text_translator(' 自动模式 '), triggered=lambda: self.react('Auto'),icon=QtGui.QIcon('correct.svg')),
                'Global': QtWidgets.QAction(self.text_translator(' 全局模式 '), triggered=lambda: self.react('Global'),icon=QtGui.QIcon('correct.svg')),
                'Direct': QtWidgets.QAction(self.text_translator(' 直连模式 '), triggered=lambda: self.react('Direct'),icon=QtGui.QIcon('correct.svg')),
                'AutoStartup': QtWidgets.QAction(self.text_translator(' 开机自启 '), triggered=lambda: self.react('AutoStartup')),
                'AllowUWP': QtWidgets.QAction(self.text_translator(' 允许UWP '), triggered=lambda: self.react('AllowUWP'),icon=QtGui.QIcon('hook.svg')),
                'Close': QtWidgets.QAction(self.text_translator(' 退出 '), triggered=lambda: self.react('Close'))}
            self.w = QtWidgets.QWidget()
            self.tp = QtWidgets.QSystemTrayIcon()
            self.tp.activated.connect(self.activate)
            if self.is_light_Theme():
                self.tp.setIcon(QtGui.QIcon('light_mode_icon.svg'))
            else:
                self.tp.setIcon(QtGui.QIcon('dark_mode_icon.svg'))
            self.tpmen = QtWidgets.QMenu()
            if self.language == 'zh-Hans-CN':
                self.tpmen.setStyleSheet('''QMenu {background-color:#ffffff; font-size:10pt; font-family:Microsoft Yahei; color: #333333; border:2px solid #eeeeee; border-radius: 6px;}
                                       QMenu::item:selected {background-color:#eeeeee; color:#333333; padding:8px 10px 8px 10px; border:2px solid #eeeeee; border-radius:4;}
                                       QMenu::item {background-color:#ffffff;padding:8px 10px 8px 10px; border:2px solid #ffffff; border-radius:4;}
                                       QMenu::icon {padding:8px 6px 8px 6px;}''')
            else:
                self.tpmen.setStyleSheet('''QMenu {background-color:#ffffff; font-size:10pt; font-family:Arial; color: #333333; border:2px solid #eeeeee; border-radius: 6px;}
                                       QMenu::item:selected {background-color:#eeeeee; color:#333333; padding:8px 10px 8px 10px; border:2px solid #eeeeee; border-radius:4;}
                                       QMenu::item {background-color:#ffffff;padding:8px 10px 8px 10px; border:2px solid #ffffff; border-radius:4;}
                                       QMenu::icon {padding:8px 6px 8px 6px;}''')
            self.tpmen.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
            self.tpmen.setWindowFlag(QtCore.Qt.FramelessWindowHint)
            self.tpmen.setWindowFlag(QtCore.Qt.NoDropShadowWindowHint)
            self.init()
            self.tp.show()
        except Exception as error:
            if not 'Yashmak has already lunched' in error:
                self.exit()
                self.pop_message('未知错误启动失败')
            else:
                self.kill()
            self.tp.hide()
            self.w.deleteLater()
            self.w.close()
            raise Exception
        else:
            if os.path.exists('Config/new.json'):
                self.pop_message('Yashmak更新成功')
                os.remove('Config/new.json')
            else:
                self.pop_message('已启动并成功连接')
            self.tpmen.popup(QtCore.QPoint(0, 0))
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self.close_menu)
            self.timer.start(10)

    def react(self,message):
        if message in ['Auto','Global','Direct']:
            self.change_mode(message)
        elif message == 'Close':
            self.exit()
            self.pop_message('已退出并断开连接')
            self.tp.hide()
            self.w.hide()
            time.sleep(1)
            self.w.close()
        elif message == 'AutoStartup':
            self.change_startup_policy()
        elif message == 'AllowUWP':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 0)
            self.pop_message('已允许UWP应用连接代理')
        self.tpmen.update()

    def change_startup_policy(self):
        reverse = {'auto': 'manual', 'manual': 'auto'}
        path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        if os.path.exists(path):
            with open(path, 'r') as file:
                content = file.read()
            content = self.translate(content)
            config = json.loads(content)
        self.edit_config('startup', reverse[config['startup'].lower()])
        if config['startup'].lower() == 'auto':
            self.auto_startup(False)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
            self.pop_message('已取消开机自启')
        elif config['startup'].lower() == 'manual':
            self.auto_startup(True)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
            self.pop_message('已设置开机自启')

    def init(self):
        path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        if os.path.exists(path):
            with open(path, 'r') as file:
                content = file.read()
            content = self.translate(content)
            config = json.loads(content)
        if config['mode'].lower() == 'auto':
            self.set_mode_UI('Auto')
        elif config['mode'].lower() == 'global':
            self.set_mode_UI('Global')
        elif config['mode'].lower() == 'direct':
            self.set_mode_UI('Direct')
        if config['startup'].lower() == 'auto':
            self.auto_startup(True)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
        elif config['startup'].lower() == 'manual':
            self.auto_startup(False)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
        self.init_menu()

    def exit(self):
        platform = sys.platform
        if platform == 'win32':
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0,winreg.KEY_ALL_ACCESS)
            ENVIRONMENT_SETTING = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_ALL_ACCESS)

            def set_key(root, name, value):
                try:
                    _, reg_type = winreg.QueryValueEx(root, name)
                    winreg.SetValueEx(root, name, 0, reg_type, value)
                except Exception:
                    if type(value) == type("a"):
                        reg_type = 1
                    elif type(value) == type(1):
                        reg_type = 4
                    winreg.SetValueEx(root, name, 0, reg_type, value)

            def delete_key(root, name):
                try:
                    winreg.DeleteValue(root, name)
                except Exception:
                    pass

            set_key(INTERNET_SETTINGS, 'ProxyEnable', 0)
            delete_key(ENVIRONMENT_SETTING, 'HTTP_PROXY')
            delete_key(ENVIRONMENT_SETTING, 'HTTPS_PROXY')
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, 37, 0, 0)
            internet_set_option(0, 39, 0, 0)
        elif platform == 'darwin':
            os.popen('''networksetup -setwebproxystate "Wi-Fi" off''')
            os.popen('''networksetup -setsecurewebproxystate "Wi-Fi" off''')
            os.popen('''networksetup -setwebproxystate "Ethernet" off''')
            os.popen('''networksetup -setsecurewebproxystate "Ethernet" off''')
        self.kill()

    def auto_startup(self, enable):
        location = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Yashmak.lnk"
        try:
            os.remove(location)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        if enable:
            self.make_link(location,os.path.abspath(os.path.dirname(sys.argv[0])) + "\Verify.exe")
        else:
            self.make_link(location,os.path.abspath(os.path.dirname(sys.argv[0])) + "\Recover.exe")

    def enable_loopback_UWPs(self):
        os.popen("CheckNetIsolation.exe loopbackexempt -c")
        MAPPINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings',0, winreg.KEY_ALL_ACCESS)
        for x in range(winreg.QueryInfoKey(MAPPINGS)[0]):
            try:
                os.popen("CheckNetIsolation.exe loopbackexempt -a -p=" + winreg.EnumKey(MAPPINGS, x))
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    def is_light_Theme(self):
        try:
            PERSONALIZE = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize', 0,winreg.KEY_ALL_ACCESS)
            value, _ = winreg.QueryValueEx(PERSONALIZE, 'SystemUsesLightTheme')
            return value
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            return True

    def detect_language(self):
        try:
            USER_PROFILE = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Control Panel\International\User Profile', 0,winreg.KEY_ALL_ACCESS)
            value, _ = winreg.QueryValueEx(USER_PROFILE, 'Languages')
            return value
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            return ['']

    def kill(self):
        global process1
        try:
            while process1.is_alive():
                process1.kill()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def daemon(self,children, father):
        while 1:
            if father not in psutil.pids():
                for child in children:
                    try:
                        child.kill()
                    except Exception as error:
                        traceback.clear_frames(error.__traceback__)
                        error.__traceback__ = None
                break
            time.sleep(10)

    def run(self):
        repaired = 0
        while True:
            path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/pid'
            try:
                if os.path.exists(path):
                    with open(path, 'r') as file:
                        pid = int(file.read())
                    if pid in psutil.pids() and psutil.Process(pid).name().lower() == 'yashmak.exe':
                        raise Exception('Yashmak has already lunched')
            except Exception as error:
                if 'Yashmak has already lunched' in error:
                    raise Exception('Yashmak has already lunched')
            global process1
            process1 = multiprocessing.Process(target=yashmak)
            process1.daemon = True
            process1.start()
            time.sleep(1)
            if not process1.is_alive() and repaired < 1:
                self.repair('chinalist.json')
                repaired += 1
            elif not process1.is_alive() and repaired == 1:
                self.repair('old.json')
                repaired += 1
            elif not process1.is_alive() and repaired >= 2:
                raise Exception('Unknown Error')
            else:
                break

    def edit_config(self,key, value):
        path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        if os.path.exists(path):
            with open(path, 'r') as file:
                content = file.read()
            content = self.translate(content)
            config = json.loads(content)
        config[key] = value
        with open(path, 'w') as file:
            json.dump(config, file, indent=4)

    def translate(self,content):
        return content.replace('\\', '/')

    def make_link(self,location, target):
        shortcut = '''"''' + os.path.abspath(os.path.dirname(sys.argv[0])) + '/Shortcut.exe" /f:'
        working_dir = '''/w:"''' + os.path.abspath(os.path.dirname(sys.argv[0])) + '''"'''
        os.popen(shortcut + '''"''' + location + '''" /a:c /t:"''' + target + '''" ''' + working_dir)

    def repair(self,filename):
        with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup/' + filename, 'rb') as bkfile:
            with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/chinalist.json', 'wb') as ofile:
                ofile.write(bkfile.read())

    def option_switcher(self,items,target):
        for x in items:
            if x == target:
                self.actions[x].setIconVisibleInMenu(True)
            else:
                self.actions[x].setIconVisibleInMenu(False)

    def init_menu(self):
        item = ['Auto','Global','Direct','Separator','AutoStartup','AllowUWP','Close']
        for x in item:
            if x == 'Separator':
                self.tpmen.addSeparator()
            elif x in self.actions:
                self.tpmen.addAction(self.actions[x])

    def change_mode(self,mode):
        mes = {'Auto':'已设置为自动模式','Global':'已设置为全局模式','Direct':'已设置为直连模式'}
        self.kill()
        self.edit_config('mode', mode.lower())
        self.run()
        self.pop_message(mes[mode])
        self.set_mode_UI(mode)

    def set_mode_UI(self,mode):
        self.option_switcher(['Auto', 'Global', 'Direct'], mode)

    def text_translator(self,message):
        translations = {'已启动并成功连接': 'Launched and successfully connected',
                        'Yashmak更新成功': 'Yashmak successfully updated',
                        '未知错误启动失败': 'Unknown Error Failed to launch',
                        '已允许UWP应用连接代理': 'UWP apps have been allowed to connect to the proxy',
                        '已设置开机自启': 'Auto startup has been enabled', '已取消开机自启': 'Auto startup has been disabled',
                        '已退出并断开连接': 'Exited and disconnected', '已设置为直连模式': 'Has set to Direct Mode',
                        '已设置为全局模式': 'Has set to Global Mode', '已设置为自动模式': 'Has set to Auto Mode',
                        ' 自动模式 ': ' Auto Mode', ' 全局模式 ':' Global Mode', ' 直连模式 ':' Direct Mode',
                        ' 开机自启 ': ' Auto Startup', ' 允许UWP ': ' Allow UWP', ' 退出 ': ' Exit'}
        if self.language == 'zh-Hans-CN':
            return message
        elif message in translations:
            return translations[message]
        else:
            return 'ERROR'

    def pop_message(self,message):
        self.tp.showMessage('Yashmak', self.text_translator(message), msecs=1000)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('windowsvista')
    window = windows()
    sys.exit(app.exec_())