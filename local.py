from PyQt6 import QtWidgets, QtGui, QtCore
from dns import message
import aioprocessing
import threading
import asyncio
import socket
import ssl
import base64
import gzip
import json
import os
import signal
import sys
import ipaddress
import traceback
import time
import datetime
import random
import gc
import win32api
import win32gui
import win32con
import win32print
import winreg
import ctypes
import psutil


class yashmak_base():
    @staticmethod
    async def clean_up(writer1=None, writer2=None):
        try:
            if writer1 != None:
                writer1.close()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                writer2.close()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer1 != None:
                await writer1.wait_closed()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                await writer2.wait_closed()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    @staticmethod
    def set_priority(level):
        p = psutil.Process(os.getpid())
        if level.lower() == 'real_time':
            p.nice(psutil.REALTIME_PRIORITY_CLASS)
        elif level.lower() == 'high':
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        elif level.lower() == 'above_normal':
            p.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'normal':
            p.nice(psutil.NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'below_normal':
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'idle':
            p.nice(psutil.IDLE_PRIORITY_CLASS)
        else:
            raise Exception('Unexpected value')

    @staticmethod
    def is_ip(host):
        try:
            if b':' in host or int(host[host.rfind(b'.') + 1:]):
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    @staticmethod
    def get_today():
        today = int(str(datetime.datetime.utcnow())[:10].replace('-', '')) ** 3
        return int(str(today)[today % 8:8] + str(today)[0:today % 8])

    @staticmethod
    def translate(content):
        return content.replace('\\', '/')

    @staticmethod
    def encode(data):
        return data.encode('utf-8')

    @staticmethod
    async def sleep(sec):
        B = time.time()
        while time.time() - B < sec:
            S = time.time()
            await asyncio.sleep(1)
            E = time.time()
            if E - S > 2:
                return True
        return False


class yashmak_core(yashmak_base):
    def __init__(self, config, ID, response):
        try:
            #print(os.getpid(),'core')
            self.init(config, ID, response)
        except Exception as error:
            response.put(str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, ID, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.ID = ID
        self.white_list = self.config['white_list']
        self.black_list = self.config['black_list']
        self.HSTS_list = self.config['HSTS_list']
        self.geoip_list = self.config['geoip_list']
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        self.proxy_context = self.get_proxy_context()
        self.connection_pool = []
        self.connection_count = 0
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.main_port_fail = 0
        self.internet_status = (False, 0)
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    async def create_server(self):
        try:
            while True:
                sock = await self.config['pipes_sock'][self.ID][0].coro_recv()
                self.loop.create_task(self.handler(sock))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.pool())
        self.loop.create_task(self.pool_health())
        self.loop.create_task(self.white_list_updater())
        self.loop.create_task(self.clear_cache())
        self.loop.run_forever()

    async def handler(self, sock):
        try:
            data, URL, host, port, request_type = await self.process(sock)
            await self.redirect(sock,host,URL)
            await self.proxy(host,port,request_type,data,sock,self.get_type(host))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(sock)

    async def make_switches(self,sock,sr,sw,request_type):
        if request_type == 1 or request_type == 2:
            scan = True
        else:
            scan = False
        return [asyncio.create_task(self.switch_up(sock,sw,scan)),asyncio.create_task(self.switch_down(sr,sock))]

    async def switch_down(self, reader, writer):
        try:
            while 1:
                data = await reader.read(16384)
                if data == b'':
                    raise Exception
                await self.loop.sock_sendall(writer, data)
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def switch_up(self, reader, writer, scan):
        try:
            while 1:
                data = await self.loop.sock_recv(reader, 65535)
                if data == b'':
                    raise Exception
                if scan:
                    instruction = data[:4]
                    if b'GET' in instruction or b'POST' in instruction:
                        data = self.get_response(data)
                writer.write(data)
                await writer.drain()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def redirect(self, sock, host, URL):
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
                await self.http_response(sock, 301, URL)
                await self.clean_up(sock)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            raise Exception(error)

    async def proxy(self, host, port, request_type, data, sock, type):
        server_reader, server_writer = None, None
        try:
            server_reader, server_writer = await self.make_proxy(host,port,data,request_type,type,sock)
            if server_reader == None or server_writer == None:
                raise Exception
            done, pending = await asyncio.wait(await self.make_switches(sock, server_reader, server_writer, request_type),return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
            await self.clean_up(sock, server_writer)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(sock, server_writer)

    async def make_proxy(self,host,port,data,request_type,type,sock):
        server_reader, server_writer = None, None
        IPs = await self.get_IPs(type,host,sock)
        IPs_length = len(IPs)
        for x in range(IPs_length):
            address = IPs[int(random.random() * 1000 % IPs_length)]
            if type or (self.config['mode'] == 'auto' and not self.is_china_ip(address)):
                server_reader, server_writer = await self.do_handshake(host, port)
            elif address != b'127.0.0.1' and address != b'::1' and address != None:
                try:
                    server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port), 5)
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
                    continue
            elif not request_type:
                await self.http_response(sock, 404)
                raise Exception
            if not request_type:
                await self.http_response(sock, 200)
            elif data != None:
                server_writer.write(data)
                await server_writer.drain()
            break
        return server_reader, server_writer

    async def get_IPs(self,type,host,sock):
        if not type:
            try:
                IPs = await self.resolve(host)
            except Exception:
                await self.http_response(sock, 502)
                raise Exception('No IP Error')
            if IPs == None or IPs == []:
                await self.http_response(sock, 502)
                raise Exception
        else:
            IPs = [None]
        return IPs

    async def do_handshake(self,host,port):
        if len(self.connection_pool) == 0:
            server_reader, server_writer = await self.connect_proxy_server()
            server_writer.write(self.config['uuid'])
            await server_writer.drain()
        else:
            server_reader, server_writer = self.connection_pool.pop(-1)
        server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big', signed=True) + host + b'\n' + port + b'\n')
        await server_writer.drain()
        return server_reader, server_writer

    async def http_response(self, sock,type,URL=None):
        if type == 200:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n''')
        elif type == 301:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\nConnection: close\r\n\r\n''')
        elif type == 404:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 404 Not Found\r\nProxy-Connection: close\r\n\r\n''')
        elif type == 502:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 502 Bad Gateway\r\nProxy-Connection: close\r\n\r\n''')
        else:
            raise Exception('Unknown Status Code')

    def get_proxy_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context

    async def pool(self):
        self.pool_max_size = 4
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
        for port in ports:
            try:
                for IP in (await self.resolve(self.config['host'].encode('utf-8'))):
                    server_reader, server_writer = await asyncio.open_connection(host=IP,
                                                                                 port=port,
                                                                                 ssl=self.proxy_context,
                                                                                 server_hostname=self.config['host'],
                                                                                 ssl_handshake_timeout=5)
                    return server_reader, server_writer
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                if port == self.config['port'] and (await self.has_internet()):
                    self.main_port_fail += 1
        if server_reader == None or server_writer == None:
            raise Exception

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
                if await self.sleep(5):
                    self.slow_mode = False
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

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

    async def has_internet(self):
        server_writer = None
        try:
            if time.time() - self.internet_status[1] > 10:
                if socket.has_dualstack_ipv6():
                    localhost = '::1'
                else:
                    localhost = '127.0.0.1'
                server_reader, server_writer = await asyncio.open_connection(host=localhost,
                                                                             port=self.config['dns_port'])
                server_writer.write(b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83')
                await server_writer.drain()
                result = await server_reader.read(64)
                await self.clean_up(server_writer)
                if result == b'True':
                    self.internet_status = (True, time.time())
                    return True
                else:
                    self.internet_status = (False, time.time())
                    return False
            else:
                return self.internet_status[0]
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    async def white_list_updater(self):
        while True:
            try:
                self.white_list = self.white_list.union(await self.config['pipes'][self.ID][0].coro_recv())
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            await self.sleep(60)

    def exception_handler(self, loop, context):
        pass

    async def process(self, sock):
        data = await asyncio.wait_for(self.loop.sock_recv(sock, 65535), 20)
        if data == b'':
            raise Exception
        request_type = self.get_request_type(data)
        if request_type == 3:
            host, port = await self.get_socks5_address(sock)
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
            data = self.get_response(data)
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

    @staticmethod
    def get_request_type(data):
        if data[:7] == b'CONNECT':
            request_type = 0
        elif data[:3] == b'GET':
            request_type = 1
        elif data[:4] == b'POST':
            request_type = 2
        else:
            request_type = 3
        return request_type

    @staticmethod
    def get_http_address_new(data, request_type, get_url=True):
        host, port, URL = None, None, None
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

    @staticmethod
    def get_http_address_old(data, request_type):
        host, port, URL = None, None, None
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

    async def get_socks5_address(self, sock):
        host, port = None, None
        await self.loop.sock_sendall(sock, b'\x05\x00')
        data = await asyncio.wait_for(self.loop.sock_recv(sock, 65535), 20)
        if data[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, data[4:8]).encode('utf-8')
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        elif data[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, data[4:20]).encode('utf-8')
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        elif data[3] == 3:
            host = data[5:5 + data[4]]
            port = str(int.from_bytes(data[-2:], 'big')).encode('utf-8')
        await self.loop.sock_sendall(sock, b'\x05\x00\x00' + data[3:])
        return host, port

    @staticmethod
    def get_response(data):
        data = data.replace(b'http://', b'', 1)
        data = data[:data.find(b' ')+1]+data[data.find(b'/'):]
        data = data.replace(b'Proxy-', b'', 1)
        return data

    @staticmethod
    def in_it(host, var):
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

    def is_china_ip(self, ip):
        ip = ip.replace(b'::ffff:',b'',1)
        ip = int(ipaddress.ip_address(ip.decode('utf-8')))
        left = 0
        right = len(self.geoip_list) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if self.geoip_list[mid][0] <= ip <= self.geoip_list[mid][1]:
                return True
            elif self.geoip_list[mid][1] < ip:
                left = mid + 1
            elif self.geoip_list[mid][0] > ip:
                right = mid - 1
        return False

    async def resolve(self,host):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host]
        elif host in self.dns_pool and (time.time() - self.dns_ttl[host]) < 600:
            return self.dns_pool[host]
        return await self.query(host)

    async def query(self,host):
        result = await self.query_worker(host)
        if result == None:
            raise Exception
        else:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
        return result

    async def query_worker(self, host):
        server_writer = None
        try:
            if socket.has_dualstack_ipv6():
                localhost = '::1'
            else:
                localhost = '127.0.0.1'
            server_reader, server_writer = await asyncio.open_connection(host=localhost, port=self.config['dns_port'])
            server_writer.write(host)
            await server_writer.drain()
            result = (await server_reader.read(65535)).split(b',')
            await self.clean_up(server_writer)
            return result
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    async def clear_cache(self):
        while True:
            try:
                for x in list(self.dns_pool.keys()):
                    if (time.time() - self.dns_ttl[x]) > 600:
                        del self.dns_pool[x]
                        del self.dns_ttl[x]
                await self.sleep(300)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976


class yashmak_dns(yashmak_base):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'dns')
            self.init(config, response)
        except Exception as error:
            response.put(str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(700, 10, 10)
        self.config = config
        self.normal_context = self.get_normal_context()
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.ipv4 = (True, 0, 1)
        self.ipv6 = (True, 0, 1)
        self.localhost = socket.gethostname()
        self.network_interface = (socket.getaddrinfo(self.localhost,0,socket.AF_INET),
                                  socket.getaddrinfo(self.localhost,0,socket.AF_INET6))
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_server(self):
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=('::1', self.config['dns_port']), family=socket.AF_INET6,
                                            dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=('127.0.0.1', self.config['dns_port']), family=socket.AF_INET,
                                            dualstack_ipv6=False)
        return asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048)

    async def handler(self, client_reader, client_writer):
        try:
            host = await asyncio.wait_for(client_reader.read(65535), 20)
            if host != b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83':
                dns_record = await self.auto_resolve(host)
                dns_record = str(dns_record).encode('utf-8')[3:-2]
                dns_record = dns_record.replace(b"b'",b"")
                dns_record = dns_record.replace(b"'",b"")
                dns_record = dns_record.replace(b" ",b"")
                client_writer.write(dns_record)
            else:
                client_writer.write(str(await self.has_internet()).encode('utf-8'))
            await client_writer.drain()
            await self.clean_up(client_writer)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer)

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.has_internet())
        self.loop.create_task(self.clear_cache())
        self.loop.run_forever()

    @staticmethod
    def get_normal_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context

    async def network_detector_worker(self,address,q_type):
        server_writer = None
        try:
            server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=(await self.resolve(q_type,address[0].encode('utf-8')))[0], port=address[1]),2)
            await self.clean_up(server_writer)
            return 1
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)
            return 0

    async def network_detector(self,addresses,q_type):
        tasks = []
        status = await self.network_detector_worker(addresses[0],q_type)
        if status:
            return True
        for address in addresses:
            tasks.append(asyncio.create_task(self.network_detector_worker(address, q_type)))
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for x in done:
            status += x.result()
        for x in pending:
            x.cancel()
        if status:
            return True
        return False

    async def has_ipv4(self):
        tasks = [('114.114.114.114',53), ('119.29.29.29',53),('ipv4.testipv6.cn',443), ('ipv4.lookup.test-ipv6.com',443),
                 ('ipv4.test-ipv6.hkg.vr.org',443)]
        if time.time() - self.ipv4[1] > self.ipv4[2] or self.network_interface[0] != socket.getaddrinfo(self.localhost, 0, socket.AF_INET):
            result = await self.network_detector(tasks,'A')
            self.network_interface = (socket.getaddrinfo(self.localhost, 0, socket.AF_INET),
                                      self.network_interface[1])
            if not result and self.ipv4[2] < 2048:
                self.ipv4 = (result, time.time(), self.ipv4[2] * 2)
            elif result:
                self.ipv4 = (result, time.time(), 1)
            else:
                self.ipv4 = (result, time.time(), self.ipv4[2])
        return self.ipv4[0]

    async def has_ipv6(self):
        tasks = [('2400:3200:baba::1',53), ('2402:4e00::',53), ('ipv6.testipv6.cn',443), ('ipv6.lookup.test-ipv6.com',443),
                 ('ipv6.test-ipv6.hkg.vr.org',443)]
        if time.time() - self.ipv6[1] > self.ipv6[2] or self.network_interface[1] != socket.getaddrinfo(self.localhost, 0, socket.AF_INET6):
            result = await self.network_detector(tasks,'AAAA')
            self.network_interface = (self.network_interface[0],
                                      socket.getaddrinfo(self.localhost, 0, socket.AF_INET6))
            if not result and self.ipv6[2] < 2048:
                self.ipv6 = (result, time.time(), self.ipv6[2] * 2)
            elif result:
                self.ipv6 = (result, time.time(), 1)
            else:
                self.ipv6 = (result, time.time(), self.ipv6[2])
        return self.ipv6[0]

    async def has_internet(self):
        await self.has_ipv4()
        await self.has_ipv6()
        if not self.ipv4[0] and not self.ipv6[0]:
            return False
        else:
            return True

    @staticmethod
    def is_ipv6(ip):
        try:
            if b':' in ip and b'::ffff:' not in ip:
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    async def auto_resolve(self,host):
        if self.ipv4[0] and self.ipv6[0]:
            return await self.resolve('ALL', host)
        elif self.ipv4[0]:
            return await self.resolve('A', host)
        elif self.ipv6[0]:
            return await self.resolve('AAAA', host)
        else:
            raise Exception('NO Interface ERROR')

    async def resolve(self,q_type,host,doh=True):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host]
        elif host not in self.dns_pool or (time.time() - self.dns_ttl[host]) > 600:
            await self.query(host, doh)
        if q_type != 'ALL':
            return self.dns_pool[host][q_type]
        else:
            return self.dns_pool[host]['A'] + self.dns_pool[host]['AAAA']

    async def query(self,host,doh):
        ipv4 = None
        ipv6 = None
        for x in range(12):
            ipv4, ipv6 = await asyncio.gather(self.query_worker(host, 'A', doh), self.query_worker(host, 'AAAA', doh))
            if ipv4 != None and ipv6 != None:
                break
            await asyncio.sleep(0.5)
        result = {'A':ipv4,'AAAA':ipv6}
        if ipv4 != None and ipv6 != None:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()

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
            else:
                raise Exception
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
        s = None
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
            await self.clean_up(s)
        finally:
            await self.clean_up(s)

    async def get_doh_query_response(self, query, address, hostname):
        server_writer = None
        try:
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
            await self.clean_up(server_writer)
        finally:
            await self.clean_up(server_writer)

    @staticmethod
    def decode(result,type):
        IPs = []
        type = ' ' + type.upper() + ' '
        position = result.find(type)
        if position < 0:
            return []
        while position > 0:
            IPs.append(result[position + len(type):result.find('\n', position)].encode('utf-8'))
            position = result.find(type, position + len(type))
        return IPs

    async def clear_cache(self):
        while True:
            try:
                if await self.has_internet():
                    refreshable = []
                    for x in list(self.dns_pool.keys()):
                        if (time.time() - self.dns_ttl[x]) > 300:
                            refreshable.append(x)
                    self.loop.create_task(self.refresh_cache(refreshable))
                    await self.sleep(150)
                else:
                    await self.sleep(10)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def refresh_cache(self, refreshable):
        counter = 0
        refreshable_len = len(refreshable)
        while True:
            for x in range(10):
                counter += 1
                if counter <= refreshable_len:
                    self.loop.create_task(self.query(refreshable[counter - 1],True))
                else:
                    return 0

    def exception_handler(self, loop, context):
        pass


class yashmak_log(yashmak_base):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'log')
            self.init(config, response)
        except Exception as error:
            response.put(str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.white_list = self.config['white_list']
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        self.proxy_context = self.get_proxy_context()
        self.backup(self.config['white_list_path'], 'old.json')
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.main_port_fail = 0
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.white_list_updater())
        self.loop.run_forever()

    async def connect_proxy_server(self):
        server_reader, server_writer = None, None
        if self.main_port_fail <= 100:
            ports = [self.config['port'], self.get_calculated_port()]
        else:
            ports = [self.get_calculated_port()]
        for port in ports:
            try:
                for IP in (await self.resolve(self.config['host'].encode('utf-8'))):
                    server_reader, server_writer = await asyncio.open_connection(host=IP,
                                                                                 port=port,
                                                                                 ssl=self.proxy_context,
                                                                                 server_hostname=self.config['host'],
                                                                                 ssl_handshake_timeout=5)
                    return server_reader, server_writer
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                if port == self.config['port'] and (await self.has_internet()):
                    self.main_port_fail += 1
        if server_reader == None or server_writer == None:
            raise Exception

    async def has_internet(self):
        server_writer = None
        try:
            if socket.has_dualstack_ipv6():
                localhost = '::1'
            else:
                localhost = '127.0.0.1'
            server_reader, server_writer = await asyncio.open_connection(host=localhost, port=self.config['dns_port'])
            server_writer.write(b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83')
            await server_writer.drain()
            result = await server_reader.read(64)
            await self.clean_up(server_writer)
            if result == b'True':
                return True
            else:
                return False
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    def get_proxy_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context

    async def white_list_updater(self):
        while True:
            try:
                self.white_list_old = self.white_list.copy()
                customize = await self.white_list_update_worker()
                if customize:
                    if os.path.exists(self.config['white_list_path']):
                        with open(self.config['white_list_path'], 'r') as file:
                            data = json.load(file)
                    else:
                        data = []
                    customize = json.loads(gzip.decompress(customize))
                    data += customize
                    for x in list(map(self.encode, customize)):
                        self.white_list.add(x.replace(b'*', b''))
                    data = list(set(data))
                    self.backup(self.config['white_list_path'],'chinalist.json')
                    await asyncio.sleep(1)
                    with open(self.config['white_list_path'], 'w') as file:
                        json.dump(data, file)
                    self.push_white_list()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            await self.sleep(60)

    async def white_list_update_worker(self):
        server_writer = None
        try:
            server_reader, server_writer = await self.connect_proxy_server()
            server_writer.write(self.config['uuid'])
            await server_writer.drain()
            server_writer.write(int.to_bytes(-3, 2, 'big', signed=True))
            await server_writer.drain()
            customize = b''
            while True:
                data = await server_reader.read(16384)
                if data == b'' or data == b'\n':
                    break
                customize += data
            await self.clean_up(server_writer)
            return customize
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    @staticmethod
    def backup(path,filename):
        os.makedirs(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup', exist_ok=True)
        with open(path,'rb') as ofile:
            with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup/' + filename, 'wb') as bkfile:
                bkfile.write(ofile.read())
                bkfile.flush()

    def push_white_list(self):
        difference = self.white_list.symmetric_difference(self.white_list_old)
        for x in self.config['pipes'].keys():
            self.config['pipes'][x][1].send(difference)

    async def resolve(self,host):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host]
        elif host in self.dns_pool and (time.time() - self.dns_ttl[host]) < 600:
            return self.dns_pool[host]
        return await self.query(host)

    async def query(self,host):
        result = await self.query_worker(host)
        if result == None:
            raise Exception
        else:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
        return result

    async def query_worker(self, host):
        server_writer = None
        try:
            if socket.has_dualstack_ipv6():
                localhost = '::1'
            else:
                localhost = '127.0.0.1'
            server_reader, server_writer = await asyncio.open_connection(host=localhost, port=self.config['dns_port'])
            server_writer.write(host)
            await server_writer.drain()
            result = (await server_reader.read(65535)).split(b',')
            await self.clean_up(server_writer)
            return result
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    async def clear_cache(self):
        while 1:
            try:
                for x in list(self.dns_pool.keys()):
                    if (time.time() - self.dns_ttl[x]) > 600:
                        del self.dns_pool[x]
                        del self.dns_ttl[x]
                await self.sleep(300)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976

    def exception_handler(self, loop, context):
        pass


class yashmak_load_balancer(yashmak_base):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'lb')
            self.init(config, response)
        except Exception as error:
            response.put(str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.listener = self.get_listener()
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.run_forever()

    async def create_server(self):
        while True:
            try:
                for x in range(self.config['worker']):
                    sock, _ = await self.loop.sock_accept(self.listener)
                    await self.config['pipes_sock'][x][1].coro_send(sock)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    def get_listener(self):
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=('::', self.config['listen']), family=socket.AF_INET6,
                                            dualstack_ipv6=True, backlog=2048)
        else:
            listener = socket.create_server(address=('0.0.0.0', self.config['listen']), family=socket.AF_INET,
                                            dualstack_ipv6=False, backlog=2048)
        return listener

    def exception_handler(self, loop, context):
        pass


class yashmak_daemon(yashmak_base):
    def __init__(self, command, response):
        try:
            #print(os.getpid(),'daemon')
            self.init(command, response)
        except Exception as error:
            response.put(str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, command, response):
        gc.set_threshold(100000, 50, 50)
        self.command = command
        self.response = response
        self.service = []
        self.load_config()
        self.load_exception_list()
        self.create_pipes()
        self.find_ports()
        self.write_pid()
        self.run_service()
        self.set_priority('above_normal')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.yashmak_updater())
        self.loop.create_task(self.accept_command())
        self.loop.create_task(self.send_feedback())
        self.loop.create_task(self.check_parent())
        self.loop.run_forever()

    def run_service(self):
        information = []
        for x in range(3+self.config['worker']):
            information.append(aioprocessing.AioQueue())
        self.service.append(aioprocessing.AioProcess(target=yashmak_dns,args=(self.config,information[0],)))
        self.service.append(aioprocessing.AioProcess(target=yashmak_log, args=(self.config,information[1],)))
        self.service.append(aioprocessing.AioProcess(target=yashmak_load_balancer, args=(self.config,information[2],)))
        for x in range(self.config['worker']):
            self.service.append(aioprocessing.AioProcess(target=yashmak_core,args=(self.config,x,information[3+x],)))
        for x in self.service:
            x.start()
        result = True
        trace = []
        for x in information:
            info = x.get()
            if info != 'OK':
                result = False
                trace.append(info)
        if not result:
            self.terminate_service()
            raise Exception(str(trace))

    def terminate_service(self):
        for x in self.service:
            x.kill()

    def load_config(self):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        if os.path.exists(self.config_path + 'config.json') and os.path.exists(self.config_path + 'preference.json'):
            with open(self.config_path + 'config.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
            with open(self.config_path + 'preference.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.preference = json.loads(content)
            self.config[self.config['active']]['startup'] = self.preference['startup']
            self.config[self.config['active']]['mode'] = self.preference['mode']
            self.config[self.config['active']]['white_list_path'] = self.config_path + self.config['white_list']
            self.config[self.config['active']]['black_list_path'] = self.config_path + self.config['black_list']
            self.config[self.config['active']]['HSTS_list_path'] = self.config_path + self.config['HSTS_list']
            self.config[self.config['active']]['geoip_list_path'] = self.config_path + self.config['geoip_list']
            self.config[self.config['active']]['normal_dns'] = list(map(self.encode, self.config['normal_dns']))
            self.config[self.config['active']]['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
            self.config[self.config['active']]['worker'] = (lambda x: os.cpu_count() if x > os.cpu_count() else x)(int(self.config['worker']))
            self.config = self.config[self.config['active']]
            self.config['uuid'] = self.config['uuid'].encode('utf-8')
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'version': '','startup': '', 'mode': '', 'active': '', 'white_list': '', 'black_list': '', 'HSTS_list': '', 'geoip_list': '',
                       'normal_dns': [''], 'doh_dns': [''], 'worker': '', 'server01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}
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

        self.white_list = set()
        self.black_list = set()
        self.HSTS_list = set()
        self.geoip_list = []
        load_list(self.config['white_list_path'], self.white_list, self.encode)
        load_list(self.config['black_list_path'], self.black_list, self.encode)
        load_list(self.config['HSTS_list_path'], self.HSTS_list, self.encode)
        with open(self.config['geoip_list_path'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()
        self.config['white_list'] = self.white_list
        self.config['black_list'] = self.black_list
        self.config['HSTS_list'] = self.HSTS_list
        self.config['geoip_list'] = self.geoip_list

    def create_pipes(self):
        self.config['pipes'] = dict()
        for x in range(self.config['worker']):
            self.config['pipes'][x] = (aioprocessing.AioPipe(False))
        self.config['pipes_sock'] = dict()
        for x in range(self.config['worker']):
            self.config['pipes_sock'][x] = (aioprocessing.AioPipe(False))

    def find_ports(self):
        ports = set()
        while len(ports) < (1):
            R = str(random.randint(2000,8000))
            if os.popen("netstat -aon | findstr 127.0.0.1:" + R).read() == "" and os.popen("netstat -aon | findstr [::1]:" + R).read() == "":
                ports.add(int(R))
        ports = list(ports)
        self.config['dns_port'] = ports.pop(0)

    def write_pid(self):
        with open(self.config_path + 'pid','w') as file:
            file.write(str(os.getpid()))
            file.flush()

    async def has_internet(self):
        server_writer = None
        try:
            if socket.has_dualstack_ipv6():
                localhost = '::1'
            else:
                localhost = '127.0.0.1'
            server_reader, server_writer = await asyncio.open_connection(host=localhost, port=self.config['dns_port'])
            server_writer.write(b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83')
            await server_writer.drain()
            result = await server_reader.read(64)
            await self.clean_up(server_writer)
            if result == b'True':
                return True
            else:
                return False
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)

    async def yashmak_updater(self):
        S = 0
        while 1:
            if time.time() - S > 7200:
                while not (await self.has_internet()):
                    await self.sleep(10)
                self.update_yashmak()
                S = time.time()
            await self.sleep(300)

    def update_yashmak(self):
        try:
            if not os.path.exists(self.config_path + 'download.json'):
                win32api.ShellExecute(0, 'open', os.path.abspath(os.path.dirname(sys.argv[0])) + '/Downloader.exe', '', '', 1)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def check_parent(self):
        ppid = os.getppid()
        while True:
            if ppid not in psutil.pids():
                self.terminate_service()
                break
            await self.sleep(5)
        await self.loop.shutdown_asyncgens()
        while True:
            os.kill(os.getpid(), signal.SIGTERM)

    async def accept_command(self):
        while True:
            if await self.command.coro_get() == 'kill':
                self.terminate_service()
                break
            await asyncio.sleep(0.2)
        await self.loop.shutdown_asyncgens()
        while True:
            os.kill(os.getpid(), signal.SIGTERM)

    async def send_feedback(self):
        while True:
            if not await self.has_internet():
                self.response.put('No internet connection')
            else:
                self.response.put('OK')
            await self.sleep(10)

    def exception_handler(self, loop, context):
        pass


class yashmak_GUI(QtWidgets.QMainWindow):
    def __init__(self, screen_size):
        super(yashmak_GUI, self).__init__()
        self.init(screen_size)

    def init(self, screen_size):
        #print(os.getpid(), 'GUI')
        gc.set_threshold(100000, 50, 50)
        if ctypes.windll.shell32.IsUserAnAdmin():
            self.enable_loopback_UWPs()
            sys.exit(0)
        self.real = self.get_real(screen_size)
        self.language = self.detect_language()[0]
        self.developer = (0, time.time())
        self.init_widget()

    @staticmethod
    def get_real(screen_size):
        hDC = win32gui.GetDC(0)
        wr = win32print.GetDeviceCaps(hDC, win32con.DESKTOPHORZRES)
        hr = win32print.GetDeviceCaps(hDC, win32con.DESKTOPVERTRES)
        w = screen_size.width()
        h = screen_size.height()
        return w / wr, h / hr

    def activate(self,reason):
        if reason == QtWidgets.QSystemTrayIcon.ActivationReason.Context:
            position = win32api.GetCursorPos()
            self.tpmen.popup(QtCore.QPoint(int(position[0]*self.real[0]), int(position[1]*self.real[1])))
        elif reason == QtWidgets.QSystemTrayIcon.ActivationReason.Trigger:
            if time.time() - self.developer[1] > 3:
                self.developer = (0, time.time())
            self.developer = (self.developer[0] + 1, time.time())
            if self.developer[0] >= 5:
                os.popen("start " + os.path.abspath(os.path.dirname(sys.argv[0])) + "/Config")
                self.developer = (0, time.time())

    def close_menu(self):
        self.tpmen.close()
        self.timer.stop()

    def init_widget(self):
        try:
            self.init_SystemTray()
            self.init_SystemTray_Menu()
            self.init_elements()
            self.show_SystemTray()
            self.run()
        except Exception as error:
            self.panic(error)

    def init_SystemTray(self):
        self.w = QtWidgets.QWidget()
        self.tp = QtWidgets.QSystemTrayIcon()
        self.set_theme()
        self.tp.activated.connect(self.activate)

    def init_SystemTray_Menu(self):
        self.tpmen = QtWidgets.QMenu()
        self.set_actions()
        self.set_QSS()
        self.set_flags()

    def show_SystemTray(self):
        self.tp.show()

    def close_SystemTray(self):
        self.tp.hide()
        self.w.deleteLater()
        self.w.close()

    def set_theme(self):
        if self.is_light_Theme():
            self.tp.setIcon(QtGui.QIcon('light_mode_icon.svg'))
        else:
            self.tp.setIcon(QtGui.QIcon('dark_mode_icon.svg'))

    def set_actions(self):
        self.actions = {
            'Auto': QtGui.QAction(self.text_translator(' 自动模式 '), triggered=lambda: self.react('Auto'),icon=QtGui.QIcon('correct.svg')),
            'Global': QtGui.QAction(self.text_translator(' 全局模式 '), triggered=lambda: self.react('Global'),icon=QtGui.QIcon('correct.svg')),
            'Direct': QtGui.QAction(self.text_translator(' 直连模式 '), triggered=lambda: self.react('Direct'),icon=QtGui.QIcon('correct.svg')),
            'AutoStartup': QtGui.QAction(self.text_translator(' 开机自启 '), triggered=lambda: self.react('AutoStartup')),
            'AllowUWP': QtGui.QAction(self.text_translator(' 允许UWP '), triggered=lambda: self.react('AllowUWP'),icon=QtGui.QIcon('hook.svg')),
            'Close': QtGui.QAction(self.text_translator(' 退出 '), triggered=lambda: self.react('Close'))}

    def set_QSS(self):
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

    def set_flags(self):
        self.tpmen.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.tpmen.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        self.tpmen.setWindowFlag(QtCore.Qt.WindowType.NoDropShadowWindowHint)

    def react(self,message):
        if message in ['Auto','Global','Direct']:
            self.change_mode(message)
        elif message == 'Close':
            self.exit()
            self.pop_message('已退出并断开连接')
            time.sleep(2)
            self.close_SystemTray()
            raise Exception('EXIT')
        elif message == 'AutoStartup':
            self.change_startup_policy()
        elif message == 'AllowUWP':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 0)
            self.pop_message('已允许UWP应用连接代理')
        self.tpmen.update()

    def change_startup_policy(self):
        reverse = {'auto': 'manual', 'manual': 'auto'}
        path_preference = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/preference.json'
        if os.path.exists(path_preference):
            with open(path_preference, 'r') as file:
                content = file.read()
            content = self.translate(content)
            preference = json.loads(content)
        else:
            raise Exception
        self.edit_preference('startup', reverse[preference['startup'].lower()])
        if preference['startup'].lower() == 'auto':
            self.auto_startup(False)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
            self.pop_message('已取消开机自启')
        elif preference['startup'].lower() == 'manual':
            self.auto_startup(True)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
            self.pop_message('已设置开机自启')

    def init_elements(self):
        path_config = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        path_preference = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/preference.json'
        if os.path.exists(path_config):
            with open(path_config, 'r') as file:
                content = file.read()
            content = self.translate(content)
            config = json.loads(content)
        else:
            raise Exception
        if os.path.exists(path_preference):
            with open(path_preference, 'r') as file:
                content = file.read()
            content = self.translate(content)
            preference = json.loads(content)
        else:
            preference = {'startup': 'auto', 'mode': 'auto'}
            with open(path_preference, 'w') as file:
                json.dump(preference, file, indent=4)
        ver = config['version']
        self.tp.setToolTip('Yashmak v'+ver[0]+'.'+ver[1]+'.'+ver[2])
        if preference['mode'].lower() == 'auto':
            self.set_mode_UI('Auto')
        elif preference['mode'].lower() == 'global':
            self.set_mode_UI('Global')
        elif preference['mode'].lower() == 'direct':
            self.set_mode_UI('Direct')
        if preference['startup'].lower() == 'auto':
            self.auto_startup(True)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
        elif preference['startup'].lower() == 'manual':
            self.auto_startup(False)
            self.actions['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
        self.init_menu()

    def set_proxy(self):
        path_config = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        if os.path.exists(path_config):
            with open(path_config, 'r') as file:
                content = file.read()
            content = self.translate(content)
            config = json.loads(content)
        else:
            raise Exception
        platform = sys.platform
        if platform == 'win32':
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',0, winreg.KEY_ALL_ACCESS)
            ENVIRONMENT_SETTING = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Environment',0, winreg.KEY_ALL_ACCESS)

            def set_key(root, name, value):
                try:
                    _, reg_type = winreg.QueryValueEx(root, name)
                    winreg.SetValueEx(root, name, 0, reg_type, value)
                except Exception:
                    if isinstance(value, str):
                        reg_type = 1
                    elif isinstance(value, int):
                        reg_type = 4
                    else:
                        raise Exception
                    winreg.SetValueEx(root, name, 0, reg_type, value)

            set_key(INTERNET_SETTINGS, 'ProxyEnable', 1)
            set_key(INTERNET_SETTINGS, 'ProxyOverride', 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;windows10.microdone.cn;<local>')
            set_key(INTERNET_SETTINGS, 'ProxyServer', 'http://127.0.0.1:' + config[config['active']]['listen'])
            set_key(ENVIRONMENT_SETTING, 'HTTP_PROXY', 'http://127.0.0.1:' + config[config['active']]['listen'])
            set_key(ENVIRONMENT_SETTING, 'HTTPS_PROXY', 'http://127.0.0.1:' + config[config['active']]['listen'])
            internet_set_option = ctypes.windll.wininet.InternetSetOptionW
            internet_set_option(0, 37, 0, 0)
            internet_set_option(0, 39, 0, 0)

    @staticmethod
    def reset_proxy():
        platform = sys.platform
        if platform == 'win32':
            INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0,winreg.KEY_ALL_ACCESS)
            ENVIRONMENT_SETTING = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_ALL_ACCESS)

            def set_key(root, name, value):
                try:
                    _, reg_type = winreg.QueryValueEx(root, name)
                    winreg.SetValueEx(root, name, 0, reg_type, value)
                except Exception:
                    if isinstance(value, str):
                        reg_type = 1
                    elif isinstance(value, int):
                        reg_type = 4
                    else:
                        raise Exception
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

    def auto_startup(self, enable):
        base_path = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
        for x in os.listdir(base_path):
            if os.path.isfile(base_path+x) and "Yashmak" in x:
                try:
                    os.remove(base_path+x)
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
        location = base_path + "Yashmak" + str(random.randint(10000000,99999999)) + ".lnk"
        if enable:
            self.make_link(location,os.path.abspath(os.path.dirname(sys.argv[0])) + "\Verify.exe")
        else:
            self.make_link(location,os.path.abspath(os.path.dirname(sys.argv[0])) + "\Recover.exe")

    @staticmethod
    def enable_loopback_UWPs():
        os.popen("CheckNetIsolation.exe loopbackexempt -c")
        MAPPINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings',0, winreg.KEY_ALL_ACCESS)
        for x in range(winreg.QueryInfoKey(MAPPINGS)[0]):
            try:
                os.popen("CheckNetIsolation.exe loopbackexempt -a -p=" + winreg.EnumKey(MAPPINGS, x))
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    @staticmethod
    def is_light_Theme():
        try:
            PERSONALIZE = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize', 0,winreg.KEY_ALL_ACCESS)
            value, _ = winreg.QueryValueEx(PERSONALIZE, 'SystemUsesLightTheme')
            return value
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            return True

    @staticmethod
    def detect_language():
        try:
            USER_PROFILE = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Control Panel\International\User Profile', 0,winreg.KEY_ALL_ACCESS)
            value, _ = winreg.QueryValueEx(USER_PROFILE, 'Languages')
            return value
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            return ['']

    def kill_daemon(self):
        try:
            while self.process1.is_alive():
                self.command.put('kill')
                time.sleep(0.2)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def exit(self):
        self.reset_proxy()
        self.kill_daemon()

    def run(self, normal=True):
        repaired = 0
        spares = ['chinalist.json','old.json']
        while True:
            path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/pid'
            try:
                if os.path.exists(path):
                    with open(path, 'r') as file:
                        pid = int(file.read())
                    if pid in psutil.pids() and psutil.Process(pid).name().lower() == 'yashmak.exe':
                        raise Exception('Yashmak has already lunched')
            except Exception as error:
                if 'Yashmak has already lunched' in str(error):
                    raise Exception('Yashmak has already lunched')
            self.command = aioprocessing.AioQueue()
            self.response = aioprocessing.AioQueue()
            self.process1 = aioprocessing.AioProcess(target=yashmak_daemon, args=(self.command,self.response,))
            self.process1.start()
            info = self.response.get()
            T = threading.Thread(target=self.status_detector, args=(info,normal,))
            T.start()
            if info == 'OK' and self.process1.is_alive():
                self.set_proxy()
                break
            elif info == 'No internet connection':
                break
            else:
                self.process1.kill()
                while T.is_alive():
                    self.response.put('kill')
                    time.sleep(0.2)
            if info == 'Unable to run service' and repaired <= 1:
                self.repair(spares[repaired])
                repaired += 1
            elif 'while attempting to bind on address' in info:
                raise Exception('Yashmak has already lunched')
            else:
                raise Exception(info)

    def status_detector(self, info, normal):
        connected = False
        counter = 0
        while True:
            if info == 'kill':
                break
            elif info == 'OK' and self.process1.is_alive() and (not connected or not counter):
                connected = True
                if not counter and normal:
                    self.message_successful()
                elif counter:
                    self.pop_message('连接已恢复')
            elif info == 'No internet connection' and (connected or not counter):
                connected = False
                if not counter:
                    self.pop_message('连接失败')
                else:
                    self.pop_message('连接已中断')
            info = self.response.get()
            time.sleep(0.2)
            counter += 1

    def message_successful(self):
        if os.path.exists('Config/new.json'):
            self.pop_message('Yashmak更新成功')
            os.remove('Config/new.json')
        else:
            self.pop_message('成功连接')

    def edit_preference(self,key, value):
        path_preference = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/preference.json'
        if os.path.exists(path_preference):
            with open(path_preference, 'r') as file:
                content = file.read()
            content = self.translate(content)
            preference = json.loads(content)
        else:
            raise Exception
        preference[key] = value
        with open(path_preference, 'w') as file:
            json.dump(preference, file, indent=4)

    def panic(self, error):
        self.panic_log(str(error))
        if 'Yashmak has already lunched' in str(error):
            self.kill_daemon()
            self.pop_message('检测到运行中的Yashmak')
            time.sleep(2)
            self.close_SystemTray()
            raise Exception('EXIT')
        elif 'Expecting value' in str(error):
            self.exit()
            self.pop_message('配置文件错误')
            time.sleep(2)
            raise Exception('EXIT')
        else:
            self.exit()
            self.pop_message('未知错误')
            time.sleep(2)
            raise Exception('EXIT')

    @staticmethod
    def panic_log(error):
        if error != 'EXIT':
            path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/panic_log.txt'
            with open(path, 'a') as file:
                file.write(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()) + " " + error + "\n")
                file.flush()

    @staticmethod
    def translate(content):
        return content.replace('\\', '/')

    @staticmethod
    def make_link(location, target):
        shortcut = '''"''' + os.path.abspath(os.path.dirname(sys.argv[0])) + '/Shortcut.exe" /f:'
        working_dir = '''/w:"''' + os.path.abspath(os.path.dirname(sys.argv[0])) + '''"'''
        os.popen(shortcut + '''"''' + location + '''" /a:c /t:"''' + target + '''" ''' + working_dir)

    @staticmethod
    def repair(filename):
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
        self.kill_daemon()
        self.edit_preference('mode', mode.lower())
        self.run(False)
        self.pop_message(mes[mode])
        self.set_mode_UI(mode)

    def set_mode_UI(self,mode):
        self.option_switcher(['Auto', 'Global', 'Direct'], mode)

    def text_translator(self,message):
        translations = {'成功连接': 'Successfully connected',
                        '连接已恢复': 'Connection restored',
                        '连接失败': 'Failed to connect',
                        '连接已中断': 'Connection terminated',
                        'Yashmak更新成功': 'Yashmak successfully updated',
                        '未知错误': 'Unknown Error',
                        '配置文件错误': 'Config Error',
                        '检测到运行中的Yashmak': 'Running Yashmak has detected',
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
    GUI = yashmak_GUI(app.screens()[0].size())
    sys.exit(app.exec())
