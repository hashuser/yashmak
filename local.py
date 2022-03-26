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


class ymc_base:
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
    def translate(content):
        return content.replace('\\', '/')

    @staticmethod
    def encode(data):
        return data.encode('utf-8')

    @staticmethod
    def decode(data):
        return data.decode('utf-8')

    @staticmethod
    def base64_encode(data):
        if isinstance(data,str):
            data = data.encode('utf-8')
            return base64.b64encode(data).decode('utf-8')
        return base64.b64encode(data)

    @staticmethod
    def base64_decode(data):
        if isinstance(data,str):
            data = data.encode('utf-8')
            return base64.b64decode(data).decode('utf-8')
        return base64.b64decode(data)

    @staticmethod
    async def sleep(sec):
        if sec <= 1:
            await asyncio.sleep(sec)
        else:
            B = time.time()
            while time.time() - B < sec:
                S = time.time()
                await asyncio.sleep(1)
                E = time.time()
                if E - S > 2:
                    return True
            return False


class ymc_dns_cache(ymc_base):
    def __init__(self):
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.timeout_threshold = 600

    async def resolve(self, host):
        if self.is_ip(host):
            host = host.replace(b'::ffff:', b'')
            return [host]
        elif host in self.dns_pool and self.dns_ttl[host] > time.time():
            return self.dns_pool[host]
        return await self.dns_query(host)

    async def dns_query(self, host):
        result = await self.dns_query_worker(host)
        if result != None:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time() + self.timeout_threshold
            return result
        else:
            raise Exception('No IP Error')

    async def dns_query_worker(self, host, timeout=10):
        server_writer = None
        try:
            if socket.has_dualstack_ipv6():
                localhost = '::1'
            else:
                localhost = '127.0.0.1'
            server_reader, server_writer = await asyncio.open_connection(host=localhost, port=self.config['dns_port'])
            server_writer.write(host)
            await server_writer.drain()
            data = await asyncio.wait_for(server_reader.read(65535), timeout)
            if data == b'None':
                result = None
            elif data == b'No':
                result = []
            else:
                result = data.split(b',')
            return result
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(server_writer)

    async def dns_clear_cache(self):
        while True:
            try:
                for x in list(self.dns_pool.keys()):
                    if x in self.dns_ttl and self.dns_ttl[x] < time.time():
                        if x in self.dns_pool:
                            del self.dns_pool[x]
                        del self.dns_ttl[x]
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(int(self.timeout_threshold / 6))


class ymc_internet_status_cache(ymc_base):
    def __init__(self):
        self.internet_status = False

    def has_internet(self):
        return self.internet_status

    async def internet_refresh_cache(self):
        while True:
            server_writer = None
            try:
                if socket.has_dualstack_ipv6():
                    localhost = '::1'
                else:
                    localhost = '127.0.0.1'
                server_reader, server_writer = await asyncio.open_connection(host=localhost,port=self.config['dns_port'])
                server_writer.write(b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83')
                await server_writer.drain()
                while True:
                    result = await asyncio.wait_for(server_reader.read(64),10)
                    if result == b'True':
                        self.internet_status = True
                    else:
                        self.internet_status = False
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.clean_up(server_writer)
                await self.sleep(1)


class ymc_connect_remote_server(ymc_dns_cache):
    def __init__(self):
        super().__init__()
        self.main_port_fail = 0

    async def connect_proxy_server(self):
        server_reader, server_writer = None, None
        if self.main_port_fail <= 100:
            ports = [self.config['port'], self.get_calculated_port()]
        else:
            ports = [self.get_calculated_port()]
        for port in ports:
            try:
                for IP in (await self.resolve(self.config['host'])):
                    server_reader, server_writer = await asyncio.open_connection(host=IP,port=port,ssl=self.proxy_context,server_hostname=self.config['host'],ssl_handshake_timeout=5)
                    return server_reader, server_writer
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                if port == self.config['port'] and self.has_internet():
                    self.main_port_fail += 1
                await self.clean_up(server_writer)
        if server_reader == None or server_writer == None:
            raise Exception

    def init_proxy_context(self):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976

    @staticmethod
    def get_today():
        today = int(str(datetime.datetime.utcnow())[:10].replace('-', '')) ** 3
        return int(str(today)[today % 8:8] + str(today)[0:today % 8])


class yashmak_core(ymc_connect_remote_server, ymc_internet_status_cache):
    def __init__(self, config, ID, response):
        try:
            #print(os.getpid(),'core')
            super().__init__()
            self.init(config, ID, response)
        except Exception as error:
            response.put("yashmak_core:"+str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, ID, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.ID = ID
        self.white_list = self.config['white_list']
        self.black_list = self.config['black_list']
        self.HSTS_list = self.config['HSTS_list']
        self.EXURL_list = self.config['EXURL_list']
        self.geoip_list = self.config['geoip_list']
        self.local_ip_list = self.config['local_ip_list']
        self.connection_pool = []
        self.proxy_context = self.init_proxy_context()
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.pool())
        self.loop.create_task(self.internet_refresh_cache())
        self.loop.create_task(self.white_list_updater())
        self.loop.create_task(self.HSTS_list_updater())
        self.loop.create_task(self.push_HSTS_list())
        self.loop.create_task(self.dns_clear_cache())
        self.loop.run_forever()

    async def create_server(self):
        try:
            while True:
                sock = await self.config['pipes_sock'][self.ID][0].coro_recv()
                self.loop.create_task(self.handler(sock))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def handler(self, sock):
        try:
            data, URL, host, port, request_type = await self.process(sock)
            await self.redirect(sock,host,URL,request_type)
            await self.proxy(host,port,request_type,data,sock,self.is_abroad(host))
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
            while True:
                data = await reader.read(16384)
                if data == b'':
                    raise Exception
                await self.loop.sock_sendall(writer, data)
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(writer)

    async def switch_up(self, reader, writer, scan):
        try:
            while True:
                data = await self.loop.sock_recv(reader, 65535)
                if data == b'':
                    raise Exception
                if scan:
                    instruction = data[:4]
                    if b'GET' in instruction or b'POST' in instruction:
                        URL, host, _ = self.http_get_address_new(data, True)
                        if not await self.redirect(reader,host,URL):
                            data = self.get_response(data)
                        else:
                            continue
                writer.write(data)
                await writer.drain()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(writer)

    async def redirect(self, sock, host, URL, request_type=1):
        if URL != None and self.host_in_it(host, self.HSTS_list) and not self.URL_in_it(URL, self.EXURL_list):
            await self.http_response(sock, 301, URL)
            return True
        elif not request_type and not self.is_ip(host) and self.conclude(host) not in self.HSTS_list:
            self.HSTS_list.add(self.conclude(host))
        return False

    async def proxy(self, host, port, request_type, data, sock, abroad):
        server_reader, server_writer = None, None
        try:
            server_reader, server_writer = await self.make_proxy(host,port,data,request_type,abroad,sock)
            done, pending = await asyncio.wait(await self.make_switches(sock, server_reader, server_writer, request_type),return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(sock, server_writer)

    async def make_proxy(self,host,port,data,request_type,abroad,sock):
        server_reader, server_writer = None, None
        if not abroad:
            for address in await self.get_IPs(host, sock):
                if self.config['mode'] == 'auto' and not (self.is_china_ip(address) or self.is_local_ip(address)):
                    abroad = True
                    break
                elif address not in [b'127.0.0.1', b'::1']:
                    try:
                        server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port), 5)
                        break
                    except Exception as error:
                        traceback.clear_frames(error.__traceback__)
                        error.__traceback__ = None
                else:
                    await self.http_response(sock, 404)
                    raise Exception('Invalid address')
        if abroad:
            server_reader, server_writer = await self.do_handshake(host, port)
        if server_writer:
            if not request_type:
                await self.http_response(sock, 200)
            elif data:
                server_writer.write(data)
                await server_writer.drain()
        else:
            await self.http_response(sock, 503)
            raise Exception('Fail to connect remote server')
        return server_reader, server_writer

    async def get_IPs(self,host,sock):
        try:
            IPs = await self.resolve(host)
        except Exception:
            await self.http_response(sock, 502)
            raise Exception('No IP Error')
        return IPs

    async def do_handshake(self,host,port):
        if len(self.connection_pool) == 0:
            server_reader, server_writer = await self.connect_proxy_server()
            server_writer.write(self.config['uuid'])
        else:
            server_reader, server_writer = self.connection_pool.pop(-1)
        server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big', signed=True) + host + b'\n' + port + b'\n')
        await server_writer.drain()
        return server_reader, server_writer

    async def http_response(self, sock, code, URL=None):
        if code == 200:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 200 Connection Established\r\n\r\n''')
        elif code == 301:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\n\r\n''')
        elif code == 404:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n''')
        elif code == 502:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n''')
        elif code == 503:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n''')
        else:
            raise Exception('Unknown Status Code')

    async def pool(self):
        if self.config['mode'] == 'direct':
            return False
        else:
            self.pool_max_size = 4
            self.is_checking = 0
            self.is_connecting = 0
            self.loop.create_task(self.pool_health())
            self.loop.create_task(self.white_list_updater())
        while True:
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

    async def pool_health(self):
        while True:
            try:
                for x in list(self.connection_pool):
                    try:
                        self.is_checking += 1
                        self.connection_pool.remove(x)
                        self.loop.create_task(self.check_health(x))
                    except Exception as error:
                        traceback.clear_frames(error.__traceback__)
                        error.__traceback__ = None
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(5)

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
            await self.clean_up(x[1])

    async def white_list_updater(self):
        while True:
            try:
                self.white_list = self.white_list.union(await self.config['pipes_wl'][self.ID][0].coro_recv())
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)

    async def HSTS_list_updater(self):
        while True:
            try:
                self.HSTS_list = self.HSTS_list.union(await self.config['pipes_hs'][self.ID][0].coro_recv())
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)

    async def push_HSTS_list(self):
        self.HSTS_list_old = self.HSTS_list.copy()
        while True:
            try:
                difference = self.HSTS_list.symmetric_difference(self.HSTS_list_old)
                if difference:
                    for x in self.config['pipes_hs'].keys():
                        if x != self.ID:
                            await self.config['pipes_hs'][x][1].coro_send(difference)
                    self.HSTS_list_old = self.HSTS_list.copy()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)

    async def process(self, sock):
        data = await asyncio.wait_for(self.loop.sock_recv(sock, 65535), 20)
        if data == b'':
            raise Exception('Tunnel Timeout')
        request_type = self.get_request_type(data)
        if request_type == 3:
            host, port = await self.socks5_get_address(sock)
            data = None
            URL = None
        elif request_type == 0:
            URL, host, port = self.http_get_address_new(data, request_type)
            if host == None or port == None:
                URL, host, port = self.http_get_address_old(data, request_type)
            data = None
        else:
            URL, host, port = self.http_get_address_new(data, request_type)
            if host == None or port == None:
                URL, host, port = self.http_get_address_old(data, request_type)
            data = self.get_response(data)
        return data, URL, host, port, request_type

    def is_abroad(self, host):
        if self.config['mode'] == 'global':
            return True
        elif self.config['mode'] == 'direct':
            return False
        elif self.config['mode'] == 'auto':
            ip = self.is_ip(host)
            if not ip and self.host_in_it(host, self.black_list):
                return True
            elif not ip and not self.host_in_it(host, self.white_list):
                return True
            elif ip and not self.is_china_ip(host) and not self.is_local_ip(host):
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
    def http_get_address_new(data, request_type, get_url=True):
        host, port, URL = None, None, None
        position = data.find(b' ') + 1
        segment = data[position:data.find(b' ', position)]
        if request_type and get_url and segment[0:4] == b'http':
            URL = segment.replace(b'http', b'https', 1)
        position = data.find(b'Host: ') + 6
        if position <= 5:
            return None, None, None
        segment = data[position:data.find(b'\r\n', position)]
        if b':' in segment:
            port = segment[segment.rfind(b':') + 1:]
            host = segment[:segment.rfind(b':')]
        elif request_type == 0:
            host = segment
            port = b'443'
        else:
            host = segment
            port = b'80'
        return URL, host, port

    @staticmethod
    def http_get_address_old(data, request_type):
        host, port, URL = None, None, None
        position = data.find(b' ') + 1
        segment = data[position:data.find(b' ', position)]
        if request_type and segment[0:4] == b'http':
            URL = segment.replace(b'http', b'https', 1)
        if request_type:
            position = segment.find(b'//') + 2
            segment = segment[position:segment.find(b'/', position)]
        position = segment.rfind(b':')
        if position > 0 and position > segment.rfind(b']'):
            host = segment[:position]
            port = segment[position + 1:]
        else:
            host = segment
            port = b'80'
        host = host.replace(b'[', b'', 1)
        host = host.replace(b']', b'', 1)
        return URL, host, port

    async def socks5_get_address(self, sock):
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
    def host_in_it(host, var):
        if host in var:
            return True
        segment_length = len(host)
        while True:
            segment_length = host.rfind(b'.', 0, segment_length) - 1
            if segment_length <= -1:
                break
            if host[segment_length + 1:] in var:
                return True
        return False

    @staticmethod
    def URL_in_it(URL, var):
        URL = URL.replace(b'http://', b'', 1)
        URL = URL.replace(b'https://', b'', 1)
        segment_length = 0
        while True:
            segment_length = URL.find(b'/', segment_length + 1)
            if segment_length <= -1:
                break
            if URL[:segment_length] in var or URL[:segment_length] + b'/' in var:
                return True
        return False

    @staticmethod
    def ip_in_it(ip, var):
        ip = ip.replace(b'::ffff:',b'',1)
        ip = int(ipaddress.ip_address(ip.decode('utf-8')))
        left = 0
        right = len(var) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if var[mid][0] <= ip <= var[mid][1]:
                return True
            elif var[mid][1] < ip:
                left = mid + 1
            elif var[mid][0] > ip:
                right = mid - 1
        return False

    @staticmethod
    def conclude(data):
        def detect(data):
            if data.count(b'.') > 1:
                return True
            return False

        if detect(data):
            return data[data.find(b'.'):]
        else:
            return data

    def is_china_ip(self, ip):
        return self.ip_in_it(ip,self.geoip_list)

    def is_local_ip(self, ip):
        return self.ip_in_it(ip,self.local_ip_list)

    def exception_handler(self, loop, context):
        pass


class yashmak_dns(ymc_base):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'dns')
            self.init(config, response)
        except Exception as error:
            response.put("yashmak_dns:"+str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(700, 10, 10)
        self.config = config
        self.normal_context = self.get_normal_context()
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.dns_hit_record = dict()
        self.dns_processing = set()
        self.ipv4 = True
        self.ipv6 = True
        self.total_query = 0
        self.total_failure_query = 0
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.internet_refresh_cache())
        self.loop.create_task(self.dns_refresh_cache())
        self.loop.create_task(self.dns_clear_cache())
        self.loop.run_forever()

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
                if dns_record and dns_record != [None]:
                    dns_record = str(dns_record).encode('utf-8')[3:-2]
                    dns_record = dns_record.replace(b"b'",b"")
                    dns_record = dns_record.replace(b"'",b"")
                    dns_record = dns_record.replace(b" ",b"")
                    client_writer.write(dns_record)
                elif dns_record == [None]:
                    client_writer.write(b'No')
                else:
                    client_writer.write(b'None')
                await client_writer.drain()
            else:
                while True:
                    client_writer.write(str(self.has_internet()).encode('utf-8'))
                    await client_writer.drain()
                    await self.sleep(1)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(client_writer)

    @staticmethod
    def get_normal_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context

    async def network_detector(self,hosts,dns_server):
        for host in hosts:
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', False, dns_server, 0.5),self.dns_query_worker(host, 'AAAA', False, dns_server, 0.5))
            if ipv4 or ipv6:
                return True
        return False

    async def has_ipv4(self):
        tasks = [b'www.baidu.com', b'www.qq.com', b'www.jd.com']
        self.ipv4 = await self.network_detector(tasks, {'ipv4': True, 'ipv6': False})
        return self.ipv4

    async def has_ipv6(self):
        tasks = [b'www.baidu.com', b'www.qq.com', b'www.jd.com']
        self.ipv6 = await self.network_detector(tasks, {'ipv4': False, 'ipv6': True})
        return self.ipv6

    def has_internet(self):
        if self.ipv4 or self.ipv6:
            return True
        return False

    async def internet_refresh_cache(self):
        self.internet_failure_counter = 0
        while True:
            s = time.time()
            try:
                await asyncio.gather(self.has_ipv4(), self.has_ipv6())
                if not self.ipv4 and not self.ipv6:
                    self.internet_failure_counter += 1
                else:
                    self.internet_failure_counter = 0
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                if time.time() - s < 3:
                    await self.sleep(3)

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
        if self.ipv4 and self.ipv6:
            return await self.resolve('ALL', host)
        elif self.ipv4:
            return await self.resolve('A', host)
        elif self.ipv6:
            return await self.resolve('AAAA', host)
        else:
            return []

    async def resolve(self,q_type,host,doh=False):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host]
        elif host not in self.dns_processing and (host not in self.dns_pool or (host in self.dns_ttl and time.time() >= self.dns_ttl[host] + 480)):
            await self.wait_until_has_internet()
            await self.dns_query(host, doh)
        await self.wait_until_has_record(host)
        if host in self.dns_pool:
            self.dns_hit_record[host] = time.time() + 3600
            if q_type != 'ALL':
                return self.dns_pool[host][q_type]
            else:
                return self.dns_pool[host]['A'] + self.dns_pool[host]['AAAA']
        else:
            return []

    async def dns_query(self,host,doh):
        self.dns_processing.add(host)
        for timeout in [0.5,1,1,2,4]:
            self.total_query += 1
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', doh, timeout=timeout), self.dns_query_worker(host, 'AAAA', doh, timeout=timeout))
            if ipv4 or ipv6:
                break
            self.total_failure_query += 1
        if not ipv4 and not ipv6:
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', not doh), self.dns_query_worker(host, 'AAAA', not doh))
            if ipv4 or ipv6:
                doh = not doh
        if not ipv4:
            ipv4 = ([], 2147483647)
        if not ipv6:
            ipv6 = ([], 2147483647)
        if ipv4[0] or ipv6[0]:
            result = {'A': ipv4[0], 'AAAA': ipv6[0], 'doh': doh}
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time() + min(ipv4[1], ipv6[1])
        self.dns_processing.remove(host)

    async def dns_query_worker(self, host, q_type, doh, dns_server=None, timeout=5):
        try:
            if dns_server is None:
                dns_server = {'ipv4': True, 'ipv6': True}
            tasks = await self.dns_make_tasks(host, q_type, doh, dns_server, timeout)
            if tasks:
                done, pending, = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for x in pending:
                    x.cancel()
                results = []
                for x in range(len(done)):
                    result = done.pop().result()
                    if result:
                        results.append(result)
                if not results:
                    return None
                return self.dns_decode(results, q_type)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def dns_make_tasks(self, host, q_type, doh, dns_server, timeout):
        try:
            if q_type == 'A':
                mq_type = 1
            elif q_type == 'AAAA':
                mq_type = 28
            else:
                raise Exception
            tasks = []
            if doh:
                tasks += await self.dns_make_doh_tasks(host, mq_type, dns_server)
            else:
                tasks += self.dns_make_normal_tasks(host, mq_type, dns_server, timeout)
            return tasks
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def dns_make_doh_tasks(self, host, mq_type, dns_server):
        tasks = []
        for x in self.config['doh_dns']:
            if self.ipv4 and dns_server['ipv4']:
                v4 = await self.resolve('A', x, False)
                if v4:
                    query = message.make_query(host.decode('utf-8'), mq_type)
                    ID = query.id
                    query = query.to_wire()
                    tasks.append(asyncio.create_task(self.dns_make_doh_query(query, ID, (v4[0], 443), x)))
            if self.ipv6 and dns_server['ipv6']:
                v6 = await self.resolve('AAAA', x, False)
                if v6:
                    query = message.make_query(host.decode('utf-8'), mq_type)
                    ID = query.id
                    query = query.to_wire()
                    tasks.append(asyncio.create_task(self.dns_make_doh_query(query, ID, (v6[0], 443), x)))
        return tasks

    def dns_make_normal_tasks(self, host, mq_type, dns_server, timeout):
        tasks = []
        for x in self.config['normal_dns']:
            if ((not self.ipv4 and (self.ipv4 or self.ipv6)) or not dns_server['ipv4']) and not self.is_ipv6(x):
                continue
            if ((not self.ipv6 and (self.ipv4 or self.ipv6)) or not dns_server['ipv6']) and self.is_ipv6(x):
                continue
            query = message.make_query(host.decode('utf-8'), mq_type)
            ID = query.id
            query = query.to_wire()
            tasks.append(asyncio.create_task(self.dns_make_normal_query(query, ID, (x, 53), timeout)))
        return tasks

    async def dns_make_normal_query(self, query, ID, address, timeout):
        s = None
        try:
            if self.is_ipv6(address[0]):
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            await self.loop.sock_connect(s, (address[0].decode('utf-8'),address[1]))
            await self.loop.sock_sendall(s, query)
            await self.loop.sock_sendall(s, query)
            try:
                result = await asyncio.wait_for(self.loop.sock_recv(s, 512), timeout)
            except asyncio.exceptions.TimeoutError:
                raise Exception('timeout')
            return result, ID
        except Exception as error:
            if str(error) != 'timeout':
                await self.sleep(timeout)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(s)

    async def dns_make_doh_query(self, query, ID, address, hostname):
        server_writer = None
        try:
            server_reader, server_writer = await asyncio.open_connection(host=address[0],port=address[1],ssl=self.normal_context,server_hostname=hostname,ssl_handshake_timeout=2)
            server_writer.write(b'GET /dns-query?dns=' + base64.b64encode(query).rstrip(b'=') +b' HTTP/1.1\r\nHost: '+ hostname +b'\r\nContent-type: application/dns-message\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62\r\n\r\n')
            await server_writer.drain()
            result = await asyncio.wait_for(server_reader.read(16384),2)
            result = result[result.find(b'\r\n\r\n')+4:]
            return result, ID
        except Exception as error:
            await self.sleep(4)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(server_writer)

    @staticmethod
    def dns_decode(results, q_type):
        def decoder(result, ID, q_type, len_q_type):
            IPs, TTLs = [], []
            result = message.from_wire(result)
            rcode = result.rcode()
            if result.id != ID:
                raise Exception
            if rcode == 3 or rcode == 2:
                return [None], 3600
            elif rcode != 0:
                return [], 2147483647
            result = result.answer
            if not result:
                return [], 2147483647
            result = str(result.pop()) + '\n'
            position = result.find(q_type)
            if position < 0:
                return [], 2147483647
            while position > 0:
                TTLs.append(int(result[result.find(' ', position - 10) + 1:position]))
                IPs.append(result[position + len_q_type:result.find('\n', position)].encode('utf-8'))
                position = result.find(q_type, position + len_q_type)
            TTLs.sort()
            if TTLs[0] < 120:
                TTLs[0] = 120
            return IPs, TTLs[0]

        q_type = ' IN ' + q_type.upper() + ' '
        len_q_type = len(q_type)
        IPs, TTL = [], 2147483647
        for x in results:
            try:
                IPs, TTL = decoder(x[0], x[1], q_type, len_q_type)
                if not IPs:
                    continue
                break
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
        return IPs, TTL

    async def dns_refresh_cache(self):
        while True:
            s = time.time()
            try:
                if self.has_internet():
                    refreshable = []
                    for x in list(self.dns_pool.keys()):
                        if x in self.dns_ttl and time.time() >= self.dns_ttl[x]:
                            refreshable.append(x)
                    # print(refreshable)
                    await self.dns_refresh_cache_worker(refreshable)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                if time.time() - s < 5:
                    await self.sleep(5)

    async def dns_refresh_cache_worker(self, refreshable):
        for x in refreshable:
            await self.wait_until_has_internet()
            await self.wait_until_has_record(x)
            await self.dns_query(x, self.dns_pool[x]['doh'])

    async def dns_clear_cache(self):
        while True:
            try:
                for x in list(self.dns_pool.keys()):
                    if x in self.dns_hit_record and time.time() >= self.dns_hit_record[x]:
                        if x in self.dns_pool:
                            del self.dns_pool[x]
                        if x in self.dns_ttl:
                            del self.dns_ttl[x]
                        del self.dns_hit_record[x]
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)

    async def wait_until_has_internet(self):
        e = time.time() + 5
        while self.internet_failure_counter > 5 and time.time() < e:
            await self.sleep(0.5)

    async def wait_until_has_record(self, host):
        if host in self.dns_processing:
            e = time.time() + 5
            while host not in self.dns_pool and time.time() < e:
                # print('wait record', host)
                await self.sleep(0.02)

    def exception_handler(self, loop, context):
        pass


class yashmak_log(ymc_connect_remote_server, ymc_internet_status_cache):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'log')
            super().__init__()
            self.init(config, response)
        except Exception as error:
            response.put("yashmak_log:"+str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.white_list = self.config['white_list']
        self.HSTS_list = self.config['HSTS_list']
        self.backup(self.config['white_list_path'], 'old.json')
        self.proxy_context = self.init_proxy_context()
        self.set_priority('above_normal')
        response.put('OK')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.white_list_updater())
        self.loop.create_task(self.HSTS_list_updater())
        self.loop.create_task(self.internet_refresh_cache())
        self.loop.create_task(self.dns_clear_cache())
        self.loop.run_forever()

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
                    data = list(set(data))
                    len_data_old = len(data)
                    data += customize
                    data = list(set(data))
                    if len_data_old != len(data):
                        for x in list(map(self.encode, customize)):
                            self.white_list.add(x.replace(b'*', b''))
                        self.backup(self.config['white_list_path'], 'chinalist.json')
                        await asyncio.sleep(1)
                        with open(self.config['white_list_path'], 'w') as file:
                            json.dump(data, file)
                            file.flush()
                        await self.push_white_list()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
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
            return json.loads(gzip.decompress(customize))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(server_writer)

    @staticmethod
    def backup(path,filename):
        os.makedirs(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup', exist_ok=True)
        with open(path,'rb') as ofile:
            with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup/' + filename, 'wb') as bkfile:
                bkfile.write(ofile.read())
                bkfile.flush()

    async def push_white_list(self):
        difference = self.white_list.symmetric_difference(self.white_list_old)
        for x in self.config['pipes_wl'].keys():
            await self.config['pipes_wl'][x][1].coro_send(difference)

    async def HSTS_list_updater(self):
        while True:
            try:
                data = await self.config['pipes_hs'][self.config['worker']][0].coro_recv()
                self.HSTS_list = self.HSTS_list.union(data)
                HSTS = []
                for x in list(map(self.decode, self.HSTS_list)):
                    if x[0] == '.':
                        HSTS.append('*'+x)
                    else:
                        HSTS.append(x)
                HSTS = list(map(self.base64_encode, HSTS))
                with open(self.config['HSTS_list_path'], 'w') as file:
                    json.dump(HSTS,file)
                    file.flush()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)

    def exception_handler(self, loop, context):
        pass


class yashmak_load_balancer(ymc_base):
    def __init__(self, config, response):
        try:
            # print(os.getpid(),'lb')
            self.init(config, response)
        except Exception as error:
            response.put("yashmak_load_balancer:"+str(error))
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
            sock = None
            try:
                for x in range(self.config['worker']):
                    sock, _ = await self.loop.sock_accept(self.listener)
                    sock.setblocking(False)
                    await self.config['pipes_sock'][x][1].coro_send(sock)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(sock)

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


class yashmak_daemon(ymc_internet_status_cache):
    def __init__(self, command, response):
        try:
            # print(os.getpid(),'daemon')
            super().__init__()
            self.init(command, response)
        except Exception as error:
            if "yashmak_" not in str(error):
                response.put("yashmak_daemon:"+str(error))
            else:
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
        self.loop.create_task(self.check_children())
        self.loop.create_task(self.internet_refresh_cache())
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
            self.config[self.config['active']]['EXURL_list_path'] = self.config_path + self.config['EXURL_list']
            self.config[self.config['active']]['geoip_list_path'] = self.config_path + self.config['geoip_list']
            self.config[self.config['active']]['normal_dns'] = list(map(self.encode, self.config['normal_dns']))
            self.config[self.config['active']]['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
            self.config[self.config['active']]['worker'] = (lambda x: os.cpu_count() if x > os.cpu_count() else x)(int(self.config['worker']))
            self.config = self.config[self.config['active']]
            self.config['host'] = self.enhanced_base64_decode(self.config['host'])
            self.config['port'] = self.enhanced_base64_decode(self.config['port'])
            self.config['uuid'] = self.enhanced_base64_decode(self.config['uuid'])
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'version': '','startup': '', 'mode': '', 'active': '', 'white_list': '', 'black_list': '', 'HSTS2_list': '', 'EXURL_list': '','geoip_list': '',
                       'normal_dns': [''], 'doh_dns': [''], 'worker': '', 'server01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}
            with open(self.config_path + 'config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_exception_list(self):
        def load_list(location, var, funcs, replace):
            if location and not os.path.exists(location):
                with open(location, 'w') as file:
                    json.dump([],file)
                    file.flush()
            if location:
                with open(location, 'r') as file:
                    data = json.load(file)
                for func in funcs:
                    data = list(map(func, data))
                for x in data:
                    for y in replace:
                        x = x.replace(y[0], y[1], y[2])
                    var.add(x)

        self.white_list = set()
        self.black_list = set()
        self.HSTS_list = set()
        self.EXURL_list = set()
        self.geoip_list = []
        self.local_ip_list = []
        load_list(self.config['white_list_path'], self.white_list, [self.encode], [(b'*', b'', 1)])
        load_list(self.config['black_list_path'], self.black_list, [self.encode], [(b'*', b'', 1)])
        load_list(self.config['HSTS_list_path'], self.HSTS_list, [self.encode, self.base64_decode], [(b'*', b'', 1)])
        load_list(self.config['EXURL_list_path'], self.EXURL_list, [self.encode], [])
        with open(self.config['geoip_list_path'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        for x in ['10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fd00::/8','fe80::/10']:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()
        self.local_ip_list.sort()
        self.config['white_list'] = self.white_list
        self.config['black_list'] = self.black_list
        self.config['HSTS_list'] = self.HSTS_list
        self.config['EXURL_list'] = self.EXURL_list
        self.config['geoip_list'] = self.geoip_list
        self.config['local_ip_list'] = self.local_ip_list

    def create_pipes(self):
        self.config['pipes_wl'] = dict()
        self.config['pipes_hs'] = dict()
        self.config['pipes_sock'] = dict()
        for x in range(self.config['worker']):
            self.config['pipes_wl'][x] = (aioprocessing.AioPipe(False))
            self.config['pipes_hs'][x] = (aioprocessing.AioPipe(False))
            self.config['pipes_sock'][x] = (aioprocessing.AioPipe(False))
        self.config['pipes_hs'][self.config['worker']] = (aioprocessing.AioPipe(False))

    def find_ports(self):
        ports = set()
        while len(ports) < 1:
            R = str(random.randint(2000,8000))
            if os.popen("netstat -aon | findstr 127.0.0.1:" + R).read() == "" and os.popen("netstat -aon | findstr [::1]:" + R).read() == "":
                ports.add(int(R))
        ports = list(ports)
        self.config['dns_port'] = ports.pop(0)

    def write_pid(self):
        with open(self.config_path + 'pid','w') as file:
            file.write(str(os.getpid()))
            file.flush()

    async def yashmak_updater(self):
        S = 0
        while True:
            if time.time() - S > 7200:
                while not self.has_internet():
                    await self.sleep(1)
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
        await self.suicide()

    async def check_children(self):
        await self.sleep(30)
        all_alive = True
        while True:
            for x in self.service:
                if not x.is_alive():
                    all_alive = False
                    break
            if not all_alive:
                break
            await self.sleep(5)
        self.terminate_service()
        self.response.put('Panic')
        await self.sleep(1)
        await self.suicide()

    async def accept_command(self):
        while True:
            if await self.command.coro_get() == 'kill':
                self.terminate_service()
                break
            await asyncio.sleep(0.2)
        await self.suicide()

    async def send_feedback(self):
        counter = 0
        while True:
            if self.has_internet():
                self.response.put('OK')
                counter = 0
            elif counter > 3:
                self.response.put('No internet connection')
            else:
                counter += 1
            await self.sleep(1)

    async def suicide(self):
        await self.loop.shutdown_asyncgens()
        while True:
            os.kill(os.getpid(), signal.SIGTERM)

    @staticmethod
    def enhanced_base64_encode(s):
        if isinstance(s,str):
            s = s.encode('utf-8')
        a = base64.b64encode(s)
        rand = int.from_bytes(random.randbytes(len(a) + 1), 'little')
        b = base64.b64encode(int.to_bytes(rand + int.from_bytes(a, 'little'), len(a) + 2, 'little'))
        c = base64.b64encode(int.to_bytes(rand, len(a) + 1, 'little'))
        d = base64.b64encode(int.to_bytes(len(c), 3, 'little')) + c + b
        return base64.b64encode(d)

    @staticmethod
    def enhanced_base64_decode(s):
        if isinstance(s,str):
            s = s.encode('utf-8')
        a = base64.b64decode(s)
        b = int.from_bytes(base64.b64decode(a[0:4]), 'little')
        rand = int.from_bytes(base64.b64decode(a[4:b + 4]), 'little')
        c = int.from_bytes(base64.b64decode(a[b + 4:]), 'little')
        d = int.to_bytes(c - rand, len(base64.b64decode(a[4:b + 4])) - 1, 'little')
        return base64.b64decode(d)

    def exception_handler(self, loop, context):
        pass


class yashmak_GUI(QtWidgets.QMainWindow):
    def __init__(self, screen_size):
        super().__init__()
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
            set_key(INTERNET_SETTINGS, 'ProxyOverride', 'localhost;windows10.microdone.cn;<local>')
            set_key(INTERNET_SETTINGS, 'ProxyServer', '127.0.0.1:' + config[config['active']]['listen'])
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
            self.response.put('kill')
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
            elif info == 'Panic':
                self.panic(Exception('Child Process Accidentally Exit'))
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
        elif 'Child Process Accidentally Exit' in str(error):
            self.reset_proxy()
            self.pop_message('子进程意外退出')
        elif str(error) != 'EXIT':
            self.exit()
            self.pop_message('未知错误')
            time.sleep(2)
            raise Exception('EXIT')

    @staticmethod
    def panic_log(error):
        try:
            if error != 'EXIT':
                path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/panic_log.txt'
                with open(path, 'a') as file:
                    file.write(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()) + " " + error + "\n")
                    file.flush()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

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
                        '子进程意外退出': 'Child Process Accidentally Exit',
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
