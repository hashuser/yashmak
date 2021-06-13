from PyQt5 import QtWidgets, QtGui, QtCore
from dns import message
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
            self.loop = asyncio.get_event_loop()
            if socket.has_dualstack_ipv6():
                listener = socket.create_server(address=('::', self.config['listen']), family=socket.AF_INET6,
                                                dualstack_ipv6=True)
            else:
                listener = socket.create_server(address=('0.0.0.0', self.config['listen']), family=socket.AF_INET,
                                                dualstack_ipv6=False)
            server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048)
            self.context = self.get_context()
            self.connection_pool = []
            self.dns_pool = dict()
            self.dns_ttl = dict()
            self.ipv6 = False
            self.is_updating = True
            self.main_port_fail = 0
            self.backup(self.config['white_list'], 'old.json')
            self.loop.set_exception_handler(self.exception_handler)
            self.loop.create_task(server)
            #self.loop.create_task(self.TCP_ping())
            self.loop.create_task(self.pool())
            self.loop.create_task(self.pool_health())
            self.loop.create_task(self.white_list_updater())
            self.loop.create_task(self.yashmak_updater())
            self.loop.create_task(self.clear_cache())
            self.loop.create_task(self.check_parent())
            self.loop.create_task(self.ipv6_test())
            self.loop.run_forever()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def handler(self, client_reader, client_writer):
        try:
            server_writer = None
            tasks = None
            data = await asyncio.wait_for(client_reader.read(65535),20)
            if data == b'':
                raise Exception
            data, URL, host, port, request_type = await self.process(data, client_reader, client_writer)
            await self.redirect(client_writer,host,URL)
            server_reader, server_writer = await self.proxy(host,port,request_type,data,client_reader,client_writer,self.get_type(host))
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
                writer.write(b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\nConnection: close\r\n\r\n''')
                await writer.drain()
                await self.clean_up(writer)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def proxy(self, host, port, request_type, data, client_reader, client_writer, type):
        server_writer = None
        try:
            if not type:
                IPs = await self.resolve('A',host)
                if IPs == None:
                    client_writer.write(b'''HTTP/1.1 502 Bad Gateway\r\nProxy-Connection: close\r\n\r\n''')
                    await client_writer.drain()
                    raise Exception
            else:
                IPs = [None]
            IPs_length = len(IPs)
            for x in range(IPs_length):
                address = IPs[int(random.random() * 1000 % IPs_length)]
                if type or (self.config['mode'] == 'auto' and not self.is_china_ip(address)):
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
                elif address != '127.0.0.1':
                    try:
                        server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port), 5)
                    except Exception as error:
                        traceback.clear_frames(error.__traceback__)
                        error.__traceback__ = None
                        continue
                elif not request_type:
                    client_writer.write(b'''HTTP/1.1 404 Not Found\r\nProxy-Connection: close\r\n\r\n''')
                    await client_writer.drain()
                    raise Exception
                if not request_type:
                    client_writer.write(b'''HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n''')
                    await client_writer.drain()
                elif data != None:
                    server_writer.write(data)
                    await server_writer.drain()
                break
            return server_reader, server_writer
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

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
                                                                             ssl=self.context,
                                                                             server_hostname=self.config['host'],
                                                                             ssl_handshake_timeout=5)
                return server_reader, server_writer
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                if x == self.config['port']:
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

    def get_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context

    async def ipv6_test(self):
        try:
            server_writer = None
            server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host='ipv6.lookup.test-ipv6.com', port=443), 5)
            self.ipv6 = True
            await self.clean_up(server_writer, None)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer, None)

    async def resolve(self,q_type,host):
        if self.is_ip(host):
            if not self.ipv6:
                host = host.replace(b'::ffff:',b'')
            return [host]
        elif host in self.dns_pool and (time.time() - self.dns_ttl[host]) < 600:
            return self.dns_pool[host][q_type]
        return (await self.query(host))[q_type]

    async def query(self,host):
        ipv4 = None
        ipv6 = None
        for x in range(12):
            ipv4, ipv6 = await asyncio.gather(self.query_worker(host, 'A'), self.query_worker(host, 'AAAA'))
            if ipv4 != None and ipv6 != None:
                break
            await asyncio.sleep(0.5)
        result = {'A':ipv4,'AAAA':ipv6}
        if ipv4 != None and ipv6 != None:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
        return result

    async def query_worker(self, host, q_type):
        try:
            if q_type == 'A':
                mq_type = 1
            elif q_type == 'AAAA':
                mq_type = 28
            query = message.make_query(host.decode('utf-8'), mq_type)
            query = query.to_wire()
            tasks = []
            for x in self.config['dns']:
                tasks.append(asyncio.create_task(self.get_query_response(query,(x, 53))))
            done, pending = await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
            result = message.from_wire(done.pop().result())
            return self.decode(str(result), q_type)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def get_query_response(self, query, address):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            await self.loop.sock_connect(s, address)
            await self.loop.sock_sendall(s, query)
            result = await asyncio.wait_for(self.loop.sock_recv(s, 1024),4)
            return result
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(s, None)
        finally:
            await self.clean_up(s, None)

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
            self.config[self.config['active']]['dns'] = self.config['dns']
            self.config = self.config[self.config['active']]
            self.config['uuid'] = self.config['uuid'].encode('utf-8')
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'version': '','startup': '', 'mode': '', 'active': '', 'white_list': '', 'black_list': '', 'HSTS_list': '', 'geoip_list': '',
                       'dns': [''], 'server01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}
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

            def set_key(name, value):
                try:
                    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
                    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)
                except Exception:
                    if type(value) == type("a"):
                        reg_type = 1
                    elif type(value) == type(1):
                        reg_type = 4
                    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)

            set_key('ProxyEnable', 1)
            set_key('ProxyOverride', 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;windows10.microdone.cn;<local>')
            set_key('ProxyServer', 'http://127.0.0.1:'+str(self.config['listen']))
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

def exit():
    platform = sys.platform
    if platform == 'win32':
        os.popen("CheckNetIsolation.exe loopbackexempt -c")
        INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0,winreg.KEY_ALL_ACCESS)

        def set_key(name, value):
            _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
            winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)

        set_key('ProxyEnable', 0)
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, 37, 0, 0)
        internet_set_option(0, 39, 0, 0)
    elif platform == 'darwin':
        os.popen('''networksetup -setwebproxystate "Wi-Fi" off''')
        os.popen('''networksetup -setsecurewebproxystate "Wi-Fi" off''')
        os.popen('''networksetup -setwebproxystate "Ethernet" off''')
        os.popen('''networksetup -setsecurewebproxystate "Ethernet" off''')
    kill()

def enable_loopback_UWPs():
    os.popen("CheckNetIsolation.exe loopbackexempt -c")
    INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings',0, winreg.KEY_ALL_ACCESS)
    for x in range(winreg.QueryInfoKey(INTERNET_SETTINGS)[0]):
        try:
            os.popen("CheckNetIsolation.exe loopbackexempt -a -p=" + winreg.EnumKey(INTERNET_SETTINGS, x))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

def is_light_Theme():
    try:
        os.popen("CheckNetIsolation.exe loopbackexempt -c")
        INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize', 0,winreg.KEY_ALL_ACCESS)
        value, _ = winreg.QueryValueEx(INTERNET_SETTINGS, 'SystemUsesLightTheme')
        return value
    except Exception as error:
        traceback.clear_frames(error.__traceback__)
        error.__traceback__ = None
        return True

def detect_language():
    try:
        os.popen("CheckNetIsolation.exe loopbackexempt -c")
        INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Control Panel\International\User Profile', 0,winreg.KEY_ALL_ACCESS)
        value, _ = winreg.QueryValueEx(INTERNET_SETTINGS, 'Languages')
        return value
    except Exception as error:
        traceback.clear_frames(error.__traceback__)
        error.__traceback__ = None
        return ['']

def kill():
    global process1
    try:
        while process1.is_alive():
            process1.kill()
    except Exception as error:
        traceback.clear_frames(error.__traceback__)
        error.__traceback__ = None

def daemon(children,father):
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

def run():
    repaired = 0
    while True:
        path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/pid'
        if os.path.exists(path):
            with open(path, 'r') as file:
                pid = int(file.read())
            if pid in psutil.pids():
                raise Exception('Yashmak has already lunched')
        global process1
        process1 = multiprocessing.Process(target=yashmak)
        process1.daemon = True
        process1.start()
        time.sleep(1)
        if not process1.is_alive() and repaired < 1:
            repair('chinalist.json')
            repaired += 1
        elif not process1.is_alive() and repaired == 1:
            repair('old.json')
            repaired += 1
        elif not process1.is_alive() and repaired >= 2:
            raise Exception('Unknown Error')
        else:
            break

def edit_config(key,value):
    path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
    if os.path.exists(path):
        with open(path, 'r') as file:
            content = file.read()
        content = translate(content)
        config = json.loads(content)
    config[key] = value
    with open(path, 'w') as file:
        json.dump(config, file, indent=4)

def translate(content):
    return content.replace('\\', '/')

def react(message):
    global language
    if message == 'Auto':
        kill()
        edit_config('mode','auto')
        run()
        if language == 'zh-Hans-CN':
            tp.showMessage('Yashmak', '已设置为自动模式', msecs=1000)
        else:
            tp.showMessage('Yashmak', 'Has set to Auto Mode', msecs=1000)
        a.setIconVisibleInMenu(True)
        b.setIconVisibleInMenu(False)
        c.setIconVisibleInMenu(False)
    elif message == 'Global':
        kill()
        edit_config('mode','global')
        run()
        if language == 'zh-Hans-CN':
            tp.showMessage('Yashmak', '已设置为全局模式', msecs=1000)
        else:
            tp.showMessage('Yashmak', 'Has set to Global Mode', msecs=1000)
        a.setIconVisibleInMenu(False)
        b.setIconVisibleInMenu(True)
        c.setIconVisibleInMenu(False)
    elif message == 'Direct':
        kill()
        edit_config('mode','direct')
        run()
        if language == 'zh-Hans-CN':
            tp.showMessage('Yashmak', '已设置为直连模式', msecs=1000)
        else:
            tp.showMessage('Yashmak', 'Has set to Direct Mode', msecs=1000)
        a.setIconVisibleInMenu(False)
        b.setIconVisibleInMenu(False)
        c.setIconVisibleInMenu(True)
    elif message == 'Close':
        exit()
        if language == 'zh-Hans-CN':
            tp.showMessage('Yashmak', '已退出并断开连接', msecs=1000)
        else:
            tp.showMessage('Yashmak', 'Exited and disconnected', msecs=1000)
        tp.hide()
        w.hide()
        time.sleep(1)
        w.close()
    elif message == 'AutoStartup':
        path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
        if os.path.exists(path):
            with open(path, 'r') as file:
                content = file.read()
            content = translate(content)
            config = json.loads(content)
        if config['startup'].lower() == 'auto':
            target = os.path.abspath(os.path.dirname(sys.argv[0])) + "/Recover.exe"
            location = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Yashmak.lnk"
            try:
                os.remove(location)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            make_link(location, target)
            edit_config('startup','manual')
            actions[3].setIcon(QtGui.QIcon('hook.svg'))
            if language == 'zh-Hans-CN':
                tp.showMessage('Yashmak', '已取消开机自启', msecs=1000)
            else:
                tp.showMessage('Yashmak', 'Auto startup has been disabled', msecs=1000)
        else:
            target = os.path.abspath(os.path.dirname(sys.argv[0])) + "/Verify.exe"
            location = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Yashmak.lnk"
            try:
                os.remove(location)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            make_link(location, target)
            edit_config('startup','auto')
            actions[3].setIcon(QtGui.QIcon('correct.svg'))
            if language == 'zh-Hans-CN':
                tp.showMessage('Yashmak', '已设置开机自启', msecs=1000)
            else:
                tp.showMessage('Yashmak', 'Auto startup has been enabled', msecs=1000)
    elif message == 'AllowUWP':
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 0)
        if language == 'zh-Hans-CN':
            tp.showMessage('Yashmak', '已允许UWP应用连接代理', msecs=1000)
        else:
            tp.showMessage('Yashmak', 'UWP apps have been allowed to connect to the proxy', msecs=1000)
    tpmen.clear()
    tpmen.addAction(a)
    tpmen.addAction(b)
    tpmen.addAction(c)
    tpmen.addSeparator()
    tpmen.addAction(d)
    tpmen.addAction(e)
    tpmen.addAction(f)
    tp.setContextMenu(tpmen)


def init():
    a = actions[0]
    b = actions[1]
    c = actions[2]
    d = actions[3]
    e = actions[4]
    f = actions[5]
    path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/config.json'
    if os.path.exists(path):
        with open(path, 'r') as file:
            content = file.read()
        content = translate(content)
        config = json.loads(content)
    if config['mode'].lower() == 'auto':
        a.setIconVisibleInMenu(True)
        b.setIconVisibleInMenu(False)
        c.setIconVisibleInMenu(False)
    elif config['mode'].lower() == 'global':
        a.setIconVisibleInMenu(False)
        b.setIconVisibleInMenu(True)
        c.setIconVisibleInMenu(False)
    elif config['mode'].lower() == 'direct':
        a.setIconVisibleInMenu(False)
        b.setIconVisibleInMenu(False)
        c.setIconVisibleInMenu(True)
    if config['startup'].lower() == 'auto':
        target = os.path.abspath(os.path.dirname(sys.argv[0])) + "/Verify.exe"
        d.setIcon(QtGui.QIcon('correct.svg'))
    elif config['startup'].lower() == 'manual':
        target = os.path.abspath(os.path.dirname(sys.argv[0])) + "/Recover.exe"
        d.setIcon(QtGui.QIcon('hook.svg'))
    location = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Yashmak.lnk"
    try:
        os.remove(location)
    except Exception as error:
        traceback.clear_frames(error.__traceback__)
        error.__traceback__ = None
    make_link(location, target)
    e.setIcon(QtGui.QIcon('hook.svg'))
    return a, b, c, d, e, f

def make_link(location,target):
    shortcut = '''"''' + os.path.abspath(os.path.dirname(sys.argv[0]))+'/Shortcut.exe" /f:'
    working_dir = '''/w:"''' + os.path.abspath(os.path.dirname(sys.argv[0])) + '''"'''
    os.popen(shortcut + '''"''' + location + '''" /a:c /t:"''' + target + '''" ''' + working_dir)

def repair(filename):
    with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/Backup/' + filename, 'rb') as bkfile:
        with open(os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/chinalist.json', 'wb') as ofile:
            ofile.write(bkfile.read())

if __name__ == '__main__':
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            enable_loopback_UWPs()
            sys.exit(0)
        run()
        UWP = False
        language = detect_language()[0]
        app = QtWidgets.QApplication(sys.argv)
        app.setStyle('windowsvista')
        if language == 'zh-Hans-CN':
            actions = [
                QtWidgets.QAction(' 自动模式 ', triggered=lambda: react('Auto'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' 全局模式 ', triggered=lambda: react('Global'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' 直连模式 ', triggered=lambda: react('Direct'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' 开机自启 ', triggered=lambda: react('AutoStartup')),
                QtWidgets.QAction(' 允许UWP ', triggered=lambda: react('AllowUWP')),
                QtWidgets.QAction(' 退出 ', triggered=lambda: react('Close'))]
        else:
            actions = [
                QtWidgets.QAction(' Auto Mode', triggered=lambda: react('Auto'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' Global Mode', triggered=lambda: react('Global'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' Direct Mode', triggered=lambda: react('Direct'), icon=QtGui.QIcon('correct.svg')),
                QtWidgets.QAction(' Auto Startup', triggered=lambda: react('AutoStartup')),
                QtWidgets.QAction(' Allow UWP', triggered=lambda: react('AllowUWP')),
                QtWidgets.QAction(' Exit', triggered=lambda: react('Close'))]
        w = QtWidgets.QWidget()
        tp = QtWidgets.QSystemTrayIcon(w)
        if is_light_Theme():
            tp.setIcon(QtGui.QIcon('light_mode_icon.svg'))
        else:
            tp.setIcon(QtGui.QIcon('dark_mode_icon.svg'))
        tpmen = QtWidgets.QMenu()
        if language == 'zh-Hans-CN':
            tpmen.setStyleSheet('''QMenu {background-color:#f5f5f5; font-size:10pt; font-family:Microsoft Yahei; color: #333333; border:2px solid #e0e0e0; border-radius:4px;}
                                   QMenu::item:selected {background-color:#e0e0e0; color:#333333; padding:8px 10px 8px 10px;}
                                   QMenu::item {background-color:#f5f5f5;padding:8px 10px 8px 10px;}
                                   QMenu::icon {padding:8px 6px 8px 6px;}''')
        else:
            tpmen.setStyleSheet('''QMenu {background-color:#f5f5f5; font-size:10pt; font-family:Arial; color: #333333; border:2px solid #e0e0e0; border-radius:4px;}
                                   QMenu::item:selected {background-color:#e0e0e0; color:#333333; padding:8px 10px 8px 10px;}
                                   QMenu::item {background-color:#f5f5f5;padding:8px 10px 8px 10px;}
                                   QMenu::icon {padding:8px 6px 8px 6px;}''')
        tpmen.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        tpmen.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        tpmen.setWindowFlag(QtCore.Qt.NoDropShadowWindowHint)
        tp.show()
        a, b, c, d, e, f = init()
        tpmen.addAction(a)
        tpmen.addAction(b)
        tpmen.addAction(c)
        tpmen.addSeparator()
        tpmen.addAction(d)
        tpmen.addAction(e)
        tpmen.addAction(f)
        tp.setContextMenu(tpmen)
    except Exception as e:
        if not 'Yashmak has already lunched' in e:
            exit()
            if language == 'zh-Hans-CN':
                tp.showMessage('Yashmak', '未知错误启动失败', msecs=1000)
            else:
                tp.showMessage('Yashmak', 'Unknown Error Failed to launch', msecs=1000)
        else:
            kill()
        tp.hide()
        w.deleteLater()
        w.close()
        raise Exception
    else:
        if language == 'zh-Hans-CN':
            if os.path.exists('Config/new.json'):
                tp.showMessage('Yashmak', 'Yashmak更新成功', msecs=1000)
                os.remove('Config/new.json')
            else:
                tp.showMessage('Yashmak', '已启动并成功连接', msecs=1000)
        else:
            if os.path.exists('Config/new.json'):
                tp.showMessage('Yashmak', 'Yashmak successfully updated', msecs=1000)
                os.remove('Config/new.json')
            else:
                tp.showMessage('Yashmak', 'Launched and successfully connected', msecs=1000)
        app.exec()
        tp.deleteLater()
        sys.exit()