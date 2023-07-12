import asyncio
import multiprocessing
import base64
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
import ntplib
import uvloop
import random
import gc
import psutil
import platform

gc.set_threshold(100000, 50, 50)
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


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
        if "windows" in platform.system().lower():
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
        elif "linux" in platform.system().lower():
            if level.lower() == 'real_time':
                p.nice(-20)
            elif level.lower() == 'high':
                p.nice(-10)
            elif level.lower() == 'above_normal':
                p.nice(-5)
            elif level.lower() == 'normal':
                p.nice(0)
            elif level.lower() == 'below_normal':
                p.nice(5)
            elif level.lower() == 'idle':
                p.nice(20)
            else:
                raise Exception('Unexpected value')
        else:
            raise Exception('Unsupported Platform')

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


class ymc_ssl_context:
    @staticmethod
    def init_normal_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context

    def init_client_context(self, ca_path=None):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        if ca_path is None:
            ca_path = self.config_path + self.config['cert']
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(ca_path)
        return context

    def init_server_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context


class ymc_connect(ymc_ssl_context):
    async def open_connection(self,host,port,TLS=False,server_hostname=None,ssl_handshake_timeout=5,timeout=5,retry=1,context=None):
        for x in range(retry):
            try:
                if TLS:
                    if context == None:
                        context = self.init_normal_context()
                    if server_hostname == None:
                        server_hostname = host
                    if isinstance(server_hostname, bytes):
                        server_hostname = server_hostname.decode('utf-8')
                    return await asyncio.wait_for(asyncio.open_connection(host=host, port=port, ssl=context,
                                                                          server_hostname=server_hostname,
                                                                          ssl_handshake_timeout=ssl_handshake_timeout),timeout)
                else:
                    return await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
        raise Exception('Too many attempts')


class ymc_dns_parser:
    def dns_decoder(self, data, mq_type, ID, fast_mode=True):
        if fast_mode:
            return self._dns_decoder_fast(data, mq_type, ID)
        return self._dns_decoder_debug(data, mq_type, ID)

    def _dns_decoder_fast(self, data, mq_type, ID):
        result = dict()
        if isinstance(ID,bytes):
            result['ID'] = data[:2]
        else:
            result['ID'] = int.from_bytes(data[:2], 'big', signed=False)
        if result['ID'] != ID:
            return {'error':-1}
        result['flags'] = self._dns_get_flags_fast(data)
        if not result['flags']['QR']:
            return {'error':-1}
        if result['flags']['rcode'] == 3:
            return {'error':3}
        elif result['flags']['rcode']:
            return {'error':result['flags']['rcode']}
        position = data.find(b'\xc0\x0c', 12)
        if position == -1:
            result['answers'] = []
            result['error'] = None
            return result
        raw_answer = data[position:]
        result['answers'] = self._dns_get_answers_fast(raw_answer,mq_type)
        result['error'] = None
        return result

    def _dns_decoder_debug(self, data, mq_type, ID):
        result = dict()
        if isinstance(ID, bytes):
            result['ID'] = data[:2]
        else:
            result['ID'] = int.from_bytes(data[:2], 'big', signed=False)
        if result['ID'] != ID:
            return {'error':-1}
        result['flags'] = self._dns_get_flags_debug(data)
        if not result['flags']['QR']:
            return {'error':-1}
        if result['flags']['rcode'] == 3:
            return {'error':3}
        elif result['flags']['rcode']:
            return {'error':result['flags']['rcode']}
        result['questions'] = int.from_bytes(data[4:6], 'big', signed=False)
        result['answer_rrs'] = int.from_bytes(data[6:8], 'big', signed=False)
        result['authority_rrs'] = int.from_bytes(data[8:10], 'big', signed=False)
        result['additional_rrs'] = int.from_bytes(data[10:12], 'big', signed=False)
        position = data.find(b'\xc0\x0c', 12)
        if position == -1:
            result['answers'] = []
            result['queries'] = b''
            result['error'] = None
            return result
        raw_queries = data[12:position]
        result['queries'] = raw_queries
        raw_answer = data[position:]
        result['answers'] = self._dns_get_answers_debug(raw_answer,mq_type)
        result['error'] = None
        return result

    @staticmethod
    def _dns_get_answers_fast(raw_answer,mq_type):
        answers, len_raw_answer, pe = [], len(raw_answer), 0
        while True:
            ps = pe + 10
            if ps > len_raw_answer:
                break
            pe = ps + 2 + int.from_bytes(raw_answer[ps:ps + 2], 'big', signed=False)
            q_type = int.from_bytes(raw_answer[ps - 10:pe][2:4], 'big', signed=False)
            if mq_type == q_type:
                if q_type == 1:
                    rdata = socket.inet_ntop(socket.AF_INET, raw_answer[ps - 10:pe][12:]).encode('utf=8')
                elif q_type == 28:
                    rdata = socket.inet_ntop(socket.AF_INET6, raw_answer[ps - 10:pe][12:]).encode('utf=8')
                else:
                    rdata = raw_answer[ps - 10:pe][12:]
                q_ttl = int.from_bytes(raw_answer[ps - 10:pe][6:10], 'big', signed=False)
                answers.append({'q_ttl': q_ttl, 'rdata': rdata})
        return answers

    @staticmethod
    def _dns_get_answers_debug(raw_answer,mq_type):
        answers, len_raw_answer, pe = [], len(raw_answer), 0
        while True:
            ps = pe + 10
            if ps > len_raw_answer:
                break
            pe = ps + 2 + int.from_bytes(raw_answer[ps:ps + 2], 'big', signed=False)
            q_type = int.from_bytes(raw_answer[ps - 10:pe][2:4], 'big', signed=False)
            if mq_type == q_type:
                if q_type == 1:
                    rdata = socket.inet_ntop(socket.AF_INET, raw_answer[ps - 10:pe][12:]).encode('utf=8')
                elif q_type == 28:
                    rdata = socket.inet_ntop(socket.AF_INET6, raw_answer[ps - 10:pe][12:]).encode('utf=8')
                else:
                    rdata = raw_answer[ps - 10:pe][12:]
                q_ttl = int.from_bytes(raw_answer[ps - 10:pe][6:10], 'big', signed=False)
                q_class = int.from_bytes(raw_answer[ps - 10:pe][4:6], 'big', signed=False)
                answers.append({'q_type': q_type, 'q_class': q_class, 'q_ttl': q_ttl, 'rdata': rdata})
        return answers

    @staticmethod
    def _dns_get_flags_fast(data):
        flags = dict()
        raw_flags = bin(int.from_bytes(data[2:4], 'big', signed=False))
        if raw_flags[2] == '1':
            flags['QR'] = True
        else:
            flags['QR'] = False
        flags['rcode'] = int(raw_flags[14:], 2)
        return flags

    @staticmethod
    def _dns_get_flags_debug(data):
        flags = dict()
        raw_flags = bin(int.from_bytes(data[2:4], 'big', signed=False))
        if raw_flags[2] == '1':
            flags['QR'] = True
        else:
            flags['QR'] = False
        flags['opcode'] = int(raw_flags[3:7], 2)
        if raw_flags[7] == '1':
            flags['AA'] = True
        else:
            flags['AA'] = False
        if raw_flags[8] == '1':
            flags['TC'] = True
        else:
            flags['TC'] = False
        if raw_flags[9] == '1':
            flags['RD'] = True
        else:
            flags['RD'] = False
        if raw_flags[10] == '1':
            flags['RA'] = True
        else:
            flags['RA'] = False
        if raw_flags[11] == '1':
            flags['Z'] = True
        else:
            flags['Z'] = False
        if raw_flags[12] == '1':
            flags['AD'] = True
        else:
            flags['AD'] = False
        if raw_flags[13] == '1':
            flags['CD'] = True
        else:
            flags['CD'] = False
        flags['rcode'] = int(raw_flags[14:], 2)
        return flags

    def dns_encoder(self, host, mq_type, fast_mode=True):
        if fast_mode:
            return self._make_query_fast(host, mq_type)
        return False

    @staticmethod
    def _make_query_fast(host, mq_type):
        ID = random.randbytes(2)
        queries = ID + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        host = host.split(b'.')
        for x in host:
            queries += int.to_bytes(len(x), 1, 'big', signed=False) + x
        if mq_type == 1:
            queries += b'\x00\x00\x01\x00\x01'
        elif mq_type == 28:
            queries += b'\x00\x00\x1c\x00\x01'
        elif mq_type == 5:
            queries += b'\x00\x00\x05\x00\x01'
        return queries, ID


class ymc_dns_cache(ymc_base, ymc_connect):
    def __init__(self):
        self.dns_records, self.dns_futures_map = dict(), dict()
        self.dns_query_send_buffer = asyncio.Queue()

    async def connect_dns_local(self):
        if socket.has_dualstack_ipv6():
            localhost = '::1'
        else:
            localhost = '127.0.0.1'
        while True:
            try:
                self.dns_local_reader, self.dns_local_writer = await self.open_connection(localhost,self.config['dns_port'])
            except Exception as error:
                if not 'Too many attempts' in str(error):
                    raise 'Too many attempts'
            else:
                break
        self.dns_local_writer.write(b'8f1f5d11-98bc-42de-a996-e86c8c0cdf7f')
        await self.dns_local_writer.drain()
        asyncio.create_task(self.dns_query_sender())
        asyncio.create_task(self.dns_response_receiver())

    async def resolve(self, host, force=False):
        if self.is_ip(host):
            host = host.replace(b'::ffff:', b'')
            return [host]
        elif not force and host in self.dns_records:
            age = time.time() - self.dns_records[host][1]
            if 0 < age <= 600:
                asyncio.create_task(self.dns_query(host))
            elif age > 600:
                return await self.dns_query(host)
            return self.dns_records[host][0]
        return await self.dns_query(host)

    async def dns_query(self, host):
        IPs, TTL = await self.dns_query_worker(host)
        if IPs != None:
            self.dns_records[host] = (IPs, time.time() + TTL)
            return IPs
        else:
            raise Exception('No IP Error')

    async def dns_query_worker(self, host, timeout=10):
        future = asyncio.get_running_loop().create_future()
        if host in self.dns_futures_map:
            self.dns_futures_map[host].add(future)
        else:
            self.dns_futures_map[host] = {future}
        if len(self.dns_futures_map[host]) == 1:
            await self.dns_query_send_buffer.put(host)
        try:
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            while self.dns_futures_map[host]:
                future = self.dns_futures_map[host].pop()
                future.set_result((None, 0))
            return None, 0

    async def dns_query_sender(self):
        while True:
            buffer = await self.dns_query_send_buffer.get() + b'\n'
            if buffer:
                self.dns_local_writer.write(buffer)
                await self.dns_local_writer.drain()

    async def dns_response_receiver(self):
        buffer = b''
        while True:
            buffer += await self.dns_local_reader.read(65535)
            position = buffer.rfind(b'\n')
            records = buffer[:position].split(b'\n')
            buffer = buffer[position + 1:]
            for record in records:
                data = record.split(b'\r')
                host, IPs, TTL, timestamp = data[0], data[1], float(data[2]), float(data[3])
                if timestamp + 10 < time.time():
                    result = (None, TTL)
                elif IPs == b'None':
                    result = (None, TTL)
                elif IPs == b'No':
                    result = ([], TTL)
                else:
                    result = (IPs.split(b','), TTL)
                if host in self.dns_futures_map:
                    while self.dns_futures_map[host]:
                        future = self.dns_futures_map[host].pop()
                        future.set_result(result)

    async def dns_clear_cache(self):
        while True:
            try:
                for x in list(self.dns_records.keys()):
                    if self.dns_records[x][1] + 1200 < time.time():
                        del self.dns_records[x]
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(60)


class ymc_internet_status_cache(ymc_base, ymc_connect):
    def __init__(self):
        self.internet_status = None

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
                server_reader, server_writer = await self.open_connection(localhost, self.config['dns_port'])
                server_writer.write(b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83')
                await server_writer.drain()
                while True:
                    result = await asyncio.wait_for(server_reader.read(64),10)
                    if result == b'True':
                        self.internet_status = True
                    elif result == b'False':
                        self.internet_status = False
                    else:
                        self.internet_status = None
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.clean_up(server_writer)
                await self.sleep(1)


class ymc_connect_remote_server(ymc_dns_cache, ymc_internet_status_cache):
    def __init__(self):
        super().__init__()
        self.main_port_fail = 0

    async def connect_proxy_server(self, d_host=None, d_port=None, d_context=None):
        server_reader, server_writer = None, None
        if d_host is None or d_port is None or d_context is None:
            d_host = self.config['host']
            d_port = self.config['port']
            d_context = self.client_context
        if self.main_port_fail <= 100:
            ports = [d_port, self.get_calculated_port()]
        else:
            ports = [self.get_calculated_port()]
        for port in ports:
            for IP in await self.resolve(d_host):
                try:
                    server_reader, server_writer = await self.open_connection(IP, port, True, d_host, context=d_context)
                    if len(ports) == 2:
                        self.main_port_fail = 0
                    return server_reader, server_writer
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
                    await self.clean_up(server_writer)
        if self.has_internet() is True:
            self.main_port_fail += 1
        raise Exception

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976

    @staticmethod
    def get_today():
        today = int(str(datetime.datetime.utcnow())[:10].replace('-', '')) ** 3
        return int(str(today)[today % 8:8] + str(today)[0:today % 8])


class yashmak_worker(ymc_connect_remote_server):
    def __init__(self,config):
        super().__init__()
        self.config = config
        self.host_list = self.config['host_list']
        self.black_list = self.config['black_list']
        self.proxy_list = self.config['proxy_list']
        self.geoip_list = self.config['geoip_list']
        self.dns_records = self.config['dns_records']
        self.local_path = self.config['local_path']
        self.utc_difference = self.config['utc_difference']
        self.start_time = self.config['start_time']
        self.log = []
        self.log_sender_buffer = asyncio.Queue()
        self.set_priority('above_normal')
        self.create_loop()

    def create_server(self):
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET6,
                                            reuse_port=True,dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET,
                                            reuse_port=True,dualstack_ipv6=False)
        return asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048,ssl=self.init_server_context())

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.connect_dns_local())
        self.loop.create_task(self.connect_log_local())
        self.loop.run_forever()

    async def handler(self, client_reader, client_writer):
        server_reader, server_writer = None, None
        try:
            uuid = await asyncio.wait_for(client_reader.read(36),10)
            if uuid not in self.config['uuid']:
                peer = client_writer.get_extra_info("peername")[0]
                header = await self.get_complete_header(uuid,client_reader,client_writer)
                self.log.append(str((peer, str(header)[2:-1])).replace('\\\\r','\r').replace('\\\\n', '\n'))
                raise Exception
            data = 0
            while True:
                data = int.from_bytes((await asyncio.wait_for(client_reader.readexactly(2),20)), 'big',signed=True)
                if data == 0:
                    continue
                elif data > 0:
                    data = await asyncio.wait_for(client_reader.readexactly(data),20)
                    host, port = self.process(data)
                    await self.redirect(client_writer, host)
                    await self.proxy(host, port, uuid, client_reader, client_writer)
                elif data == -4:
                    await self.echo(client_writer)
                elif data == -2:
                    await self.TCP_ping(client_writer, client_reader)
                elif data == -3:
                    await self.updater(client_writer, uuid)
                else:
                    raise Exception('unknown command')
        except Exception as error:
            self.log.append("Worker_main_handler: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    async def proxy(self, host, port, uuid, client_reader, client_writer):
        server_reader, server_writer = None, None
        try:
            server_reader, server_writer = await self.make_proxy(host,port,uuid)
            if server_reader == None or server_writer == None:
                raise Exception
            done, pending = await asyncio.wait(await self.make_switches(client_reader, client_writer, server_reader, server_writer),return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
        except Exception as error:
            self.log.append("Worker_proxy: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    async def make_proxy(self, host, port, uuid):
        server_reader, server_writer = None, None
        destination = self.is_nested_proxy(host)
        if destination:
            server_reader, server_writer = await self.do_handshake(host, port, destination)
        else:
            IPs = await self.get_IPs(host)
            for x in range(len(IPs)):
                address = IPs[int(random.random() * 1000 % len(IPs))]
                self.is_china_ip(address, host, uuid)
                try:
                    server_reader, server_writer = await self.open_connection(address, port)
                    break
                except Exception as error:
                    self.log.append("Worker_make_proxy: " + str(error))
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
        if server_reader == None or server_writer == None:
            raise Exception
        return server_reader, server_writer

    def is_nested_proxy(self, host):
        for x in self.proxy_list:
            if self.host_in_it(host, self.proxy_list[x]):
                return x
        return None

    @staticmethod
    def host_in_it(host, var):
        if host in var:
            return True
        segment_length = len(host)
        for x in range(64):
            segment_length = host.rfind(b'.', 0, segment_length) - 1
            if segment_length <= -1:
                break
            if host[segment_length + 1:] in var:
                return True
        return False

    async def do_handshake(self, host, port, destination=None):
        d_host = self.config['proxy'][destination]['host']
        d_port = self.config['proxy'][destination]['port']
        d_context = self.init_client_context(self.config['proxy'][destination]['cert'])
        server_reader, server_writer = await self.connect_proxy_server(d_host, d_port, d_context)
        server_writer.write(self.config['proxy'][destination]['uuid'])
        server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big', signed=True) + host + b'\n' + port + b'\n')
        await server_writer.drain()
        return server_reader, server_writer

    async def make_switches(self,cr,cw,sr,sw):
        return [asyncio.create_task(self.switch(cr,sw)),asyncio.create_task(self.switch(sr,cw))]

    async def get_IPs(self,host,force=False):
        try:
            return await self.resolve(host,force)
        except Exception:
            return []

    @staticmethod
    def HTTP_header_decoder(header):
        lower = [b'a',b'b',b'c',b'd',b'e',b'f',b'g',b'h',b'i',b'j',b'k',b'l',b'm',b'n',b'o',b'p',b'q',b'r',b's',b't',b'u',b'v',b'w',b'x',b'y',b'z']
        number = [b'0',b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9']
        punctuation = [b'!',b'@',b'#',b'$',b'%',b'^',b'&',b'*',b'(',b')',b'-',b'=',b'_',b'+',b'{',b'}',b'[',b']',b'|',b';',b':',b',',b'.',b'/',b'<',b'>',b'?',b"'",b'"',b'~',b'`']

        def has_(value,map):
            for x in map:
                if x in value:
                    return True

        header = header.split(b'\r\n')
        sigment = header[0].split(b' ')
        if has_(sigment[0],lower) or has_(sigment[0],number) or has_(sigment[0],punctuation):
            return 400
        try:
            if b'/' not in sigment[1]:
                return 400
        except Exception:
            pass
        try:
            if sigment[2][0] == 72:
                for x in sigment[2][:5]:
                    if x not in [72,84,80,47]:
                        return 400
            elif header[1] == b'':
                return 4042
        except Exception:
            pass
        try:
            temp = sigment[2].split(b'/')[1]
            try:
                temp = float(temp)
                if temp < 1.0 or temp >= 2.0:
                    return 505
            except Exception:
                return 505
        except Exception:
            pass
        return 404

    async def get_complete_header(self, header, reader, writer):
        while True:
            try:
                result = self.HTTP_header_decoder(header)
                if b'\r\n\r\n' in header and result == 404:
                    await self.camouflage(writer, 404)
                    await asyncio.sleep(10)
                    return header
                elif result == 400:
                    await self.camouflage(writer, 400)
                    await asyncio.sleep(10)
                    return header
                elif result == 505:
                    await self.camouflage(writer, 505)
                    await asyncio.sleep(10)
                    return header
                elif result == 4042:
                    await self.camouflage(writer, 4042)
                    return header
                header += await asyncio.wait_for(reader.read(65535), 30)
            except Exception:
                return header

    async def camouflage(self,writer,type=400):
        try:
            GMT = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(self.utc_difference + time.time())).encode('utf-8')
            if type == 400:
                writer.write(b'''HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nDate: ''' + GMT + b'''\r\nContent-Type: text/html\r\nContent-Length: 150\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n''')
            elif type == 404:
                writer.write(b'''HTTP/1.1 404 Not Found\r\nServer: nginx\r\nDate: ''' + GMT + b'''\r\nContent-Type: text/html\r\nContent-Length: 146\r\nConnection: keep-alive\r\n\r\n<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n''')
            elif type == 505:
                writer.write(b'''HTTP/1.1 505 HTTP Version Not Supported\r\nServer: nginx\r\nDate: ''' + GMT + b'''\r\nContent-Type: text/html\r\nContent-Length: 180\r\nConnection: close\r\n\r\n<html>\r\n<head><title>505 HTTP Version Not Supported</title></head>\r\n<body>\r\n<center><h1>505 HTTP Version Not Supported</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n''')
            elif type == 4042:
                writer.write(b'''<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n''')
            await writer.drain()
        except Exception as error:
            self.log.append("Worker_camouflage: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(None, writer)

    async def switch(self, reader, writer):
        try:
            while True:
                data = await reader.read(32768)
                if data == b'':
                    raise Exception
                writer.write(data)
                await writer.drain()
        except BaseException as error:
            self.log.append("Worker_switch: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def TCP_ping(self, writer, reader):
        try:
            time = await asyncio.wait_for(reader.read(8), 20)
            writer.write(time)
            await writer.drain()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)
        finally:
            await asyncio.sleep(5)
            await self.clean_up(writer)

    async def echo(self, writer):
        try:
            writer.write(b'ok')
            await writer.drain()
        except Exception as error:
            self.log.append("Worker_echo: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def redirect(self, writer, host):
        try:
            URL = self.black_list[self.is_banned(host)]
            if URL != None:
                if URL[0:4] != b'http' and URL in self.black_list['tag']:
                    URL = self.black_list['tag'][URL]
                if URL[0:4] == b'http':
                    writer.write(b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\nConnection: close\r\n\r\n''')
                else:
                    writer.write(b'''HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n''')
                await writer.drain()
                await self.clean_up(writer)
        except Exception as error:
            self.log.append("Worker_redirect: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def updater(self, writer, uuid):
        try:
            if len(uuid) != 36 or b'.' in uuid or b'/' in uuid or b'\\' in uuid:
                raise Exception
            if (uuid + b'_compressed') in self.exception_list_cache:
                writer.write(self.exception_list_cache[uuid + b'_compressed'])
                await writer.drain()
            else:
                writer.write(b'\n')
                await writer.drain()
            await self.clean_up(writer)
        except Exception as error:
            self.log.append("Worker_updater: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)
    
    async def updater_cache(self):
        try:
            self.exception_list_cache = dict()
            while True:
                for uuid in self.config['uuid']:
                    path = self.local_path + '/Cache/' + uuid.decode('utf-8') + '.json'
                    if os.path.exists(path):
                        with open(path, 'rb') as file:
                            content = file.read()
                            self.exception_list_cache[uuid + b'_compressed'] = gzip.compress(content, 2)
                await asyncio.sleep(60)
        except Exception as error:
            self.log.append("Worker_updater_cache: " + str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def exception_handler(self, loop, context):
        pass

    def process(self, data):
        return self.get_address(data)

    @staticmethod
    def get_address(data):
        position = data.find(b'\n')
        host = data[:position]
        position += 1
        port = data[position:data.find(b'\n', position)]
        return host, port

    @staticmethod
    def is_ipv6(ip):
        try:
            if b':' in ip and b'::ffff:' not in ip:
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    def is_china_ip(self, ip, host, uuid):
        if self.is_ip(host):
            return False
        ip = ip.decode('utf-8')
        ip = ip.replace('::ffff:','',1)
        ip = int(ipaddress.ip_address(ip))
        left = 0
        right = len(self.geoip_list) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if self.geoip_list[mid][0] <= ip <= self.geoip_list[mid][1]:
                self.add_host(self.conclude(host), uuid)
                return True
            elif self.geoip_list[mid][1] < ip:
                left = mid + 1
            elif self.geoip_list[mid][0] > ip:
                right = mid - 1
        return False

    def is_banned(self, host):
        if host in self.black_list:
            return host
        sigment_length = len(host)
        while True:
            sigment_length = host.rfind(b'.', 0, sigment_length) - 1
            if sigment_length <= -1:
                break
            if host[sigment_length + 1:] in self.black_list:
                return host[sigment_length + 1:]
        return None

    def add_host(self, host, uuid):
        if uuid not in self.host_list:
            self.host_list[uuid] = set()
        self.host_list[uuid].add(host)

    async def write_host(self):
        while True:
            try:
                for x in self.host_list:
                    if len(self.host_list[x]) > 0:
                        await self.log_sender_buffer.put(str(list(self.host_list[x])).encode('utf-8') + b'\r\n' + x + b'\r\nhost\r\n\r\n')
                        self.host_list[x].clear()
                await asyncio.sleep(15)
            except Exception as error:
                self.log.append("Worker_write_host: " + str(error))
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def write_log(self):
        while True:
            try:
                if len(self.log) > 0:
                    await self.log_sender_buffer.put(str(self.log).encode('utf-8') + b'\r\nnone\r\nlog\r\n\r\n')
                    self.log.clear()
                await asyncio.sleep(15)
            except Exception as error:
                self.log.append("Worker_write_log: " + str(error))
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def log_sender(self, server_writer):
        while True:
            data = await self.log_sender_buffer.get()
            server_writer.write(data)
            await server_writer.drain()

    async def connect_log_local(self):
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.write_log())
        while True:
            server_writer = None
            try:
                server_reader, server_writer = await self.open_connection(host='127.0.0.1', port=self.config['log_port'])
                server_writer.write(b'f31d7515-d90f-4eba-a4a9-8eac1d0a423e')
                await server_writer.drain()
                await self.log_sender(server_writer)
            except Exception as error:
                self.log.append("Worker_connect_log_local: " + str(error))
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.clean_up(server_writer)

    @staticmethod
    def conclude(data):
        def detect(data):
            if data.count(b'.') > 1:
                return True
            return False
        if detect(data):
            return b'*' + data[data.find(b'.'):]
        else:
            return data


class yashmak_dns(ymc_base,ymc_dns_parser,ymc_connect):
    def __init__(self, config):
        try:
            #print(os.getpid(),'dns')
            self.init(config)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config):
        self.config = config
        self.dns_records, self.dns_futures_map = dict(), dict()
        self.ipv4, self.ipv6 = None, None
        self.set_priority('above_normal')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.internet_refresh_cache())
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
            if host == b'8f1f5d11-98bc-42de-a996-e86c8c0cdf7f':
                dns_response_send_buffer = asyncio.Queue()
                await asyncio.gather(self.dns_query_receiver(client_reader, dns_response_send_buffer),
                                     self.dns_response_sender(client_writer, dns_response_send_buffer))
            elif host == b'ecd465e2-4a3d-48a8-bf09-b744c07bbf83':
                await self.internet_status(client_writer)
            else:
                raise Exception('Invalid Connection')
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(client_writer)

    async def dns_query_receiver(self, client_reader, dns_response_send_buffer):
        buffer = b''
        while True:
            buffer += await client_reader.read(65535)
            position = buffer.rfind(b'\n')
            hosts = buffer[:position].split(b'\n')
            buffer = buffer[position + 1:]
            for host in hosts:
                self.loop.create_task(self.dns_query_processor(host, dns_response_send_buffer))

    @staticmethod
    async def dns_response_sender(client_writer, dns_response_send_buffer):
        while True:
            buffer = await dns_response_send_buffer.get() + b'\n'
            if buffer:
                client_writer.write(buffer)
                await client_writer.drain()

    async def dns_query_processor(self, host, dns_response_send_buffer):
        IPs, TTL = await self.auto_resolve(host)
        try:
            float(str(TTL).encode('utf-8'))
            TTL = str(TTL).encode('utf-8')
        except Exception as error:
            TTL = b'0'
        timestamp = str(time.time()).encode('utf-8')
        if IPs and IPs != [None]:
            buffer = b''
            for x in IPs:
                buffer += x + b','
            buffer = buffer[:-1]
            await dns_response_send_buffer.put(host + b'\r' + buffer + b'\r' + TTL + b'\r' + timestamp)
        elif IPs == [None]:
            await dns_response_send_buffer.put(host + b'\rNo\r' + TTL + b'\r' + timestamp)
        else:
            await dns_response_send_buffer.put(host + b'\rNone\r' + TTL + b'\r' + timestamp)

    async def internet_status(self, client_writer):
        while True:
            client_writer.write(str(self.has_internet()).encode('utf-8'))
            await client_writer.drain()
            await self.sleep(1)

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
        if self.ipv4 is False and self.ipv6 is False:
            return False
        return None

    async def internet_refresh_cache(self):
        while True:
            s = time.time()
            try:
                await asyncio.gather(self.has_ipv4(), self.has_ipv6())
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                if time.time() - s < 10:
                    await self.sleep(10)

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
            return [], None

    async def resolve(self,q_type,host,doh=False):
        if self.is_ip(host):
            host = host.replace(b'::ffff:',b'')
            return [host], 2147483647
        elif host not in self.dns_records:
            await self.dns_query(host, doh)
        elif time.time() >= self.dns_records[host][1]:
            await self.dns_query(host, doh)
        if host in self.dns_records:
            TTL = self.dns_records[host][2]
            if q_type != 'ALL':
                IPs = self.dns_records[host][0][q_type]
            else:
                IPs = self.dns_records[host][0]['A'] + self.dns_records[host][0]['AAAA']
            return IPs, TTL
        else:
            return [], None

    async def dns_query(self,host,doh):
        future = self.loop.create_future()
        if host in self.dns_futures_map:
            self.dns_futures_map[host].add(future)
        else:
            self.dns_futures_map[host] = {future}
        if len(self.dns_futures_map[host]) == 1:
            self.loop.create_task(self.dns_query_manager(host, doh))
        await future

    async def dns_query_manager(self,host,doh):
        ipv4, ipv6 = None, None
        for x in range(10):
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', doh, timeout=0.2), self.dns_query_worker(host, 'AAAA', doh, timeout=0.2))
            if ipv4 or ipv6:
                break
        if not ipv4 and not ipv6:
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', not doh), self.dns_query_worker(host, 'AAAA', not doh))
            if ipv4 or ipv6:
                doh = not doh
        if not ipv4:
            ipv4 = ([], 2147483647)
        if not ipv6:
            ipv6 = ([], 2147483647)
        if ipv4[0] or ipv6[0]:
            self.dns_records[host] = ({'A': ipv4[0], 'AAAA': ipv6[0], 'doh': doh}, time.time() + min(ipv4[1], ipv6[1]), min(ipv4[1], ipv6[1]))
        if host in self.dns_futures_map:
            while self.dns_futures_map[host]:
                future = self.dns_futures_map[host].pop()
                future.set_result(True)

    async def dns_query_worker(self, host, q_type, doh, dns_server=None, timeout=5):
        try:
            if dns_server is None:
                dns_server = {'ipv4': True, 'ipv6': True}
            mq_type = self.dns_get_mq_type(q_type)
            tasks = await self.dns_make_tasks(host, mq_type, doh, dns_server, timeout)
            if not tasks:
                return None
            done, pending, = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
            responses_raw = []
            for x in range(len(done)):
                response_raw = done.pop().result()
                if response_raw:
                    responses_raw.append(response_raw)
            if not responses_raw:
                return None
            IPs, TTL = self.dns_process_raw_responses(responses_raw, mq_type)
            if IPs and TTL:
                return IPs, TTL
            return None
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def dns_process_raw_responses(self, responses_raw, mq_type):
        for x in responses_raw:
            result = self.dns_decoder(x[0], mq_type, x[1])
            if result['error'] == None and result['answers']:
                IPs, TTLs = [], []
                for y in result['answers']:
                    IPs.append(y['rdata'])
                    TTLs.append(y['q_ttl'])
                return IPs, TTLs[0]
            elif result['error'] == 3 or result['error'] == 2:
                return [None], 3600
        return None, None

    @staticmethod
    def dns_get_mq_type(q_type):
        if q_type == 'A':
            return 1
        elif q_type == 'AAAA':
            return 28
        elif q_type == 'CNAME':
            return 5
        else:
            raise Exception

    async def dns_make_tasks(self, host, mq_type, doh, dns_server, timeout):
        try:
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
                    query, ID = self.dns_encoder(host,mq_type)
                    tasks.append(asyncio.create_task(self.dns_make_doh_query(query, ID, (v4[0], 443), x)))
            if self.ipv6 and dns_server['ipv6']:
                v6 = await self.resolve('AAAA', x, False)
                if v6:
                    query, ID = self.dns_encoder(host, mq_type)
                    tasks.append(asyncio.create_task(self.dns_make_doh_query(query, ID, (v6[0], 443), x)))
        return tasks

    def dns_make_normal_tasks(self, host, mq_type, dns_server, timeout):
        tasks = []
        for x in self.config['normal_dns']:
            if ((not self.ipv4 and (self.ipv4 or self.ipv6)) or not dns_server['ipv4']) and not self.is_ipv6(x):
                continue
            if ((not self.ipv6 and (self.ipv4 or self.ipv6)) or not dns_server['ipv6']) and self.is_ipv6(x):
                continue
            query, ID = self.dns_encoder(host, mq_type)
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
            try:
                result = await asyncio.wait_for(self.loop.sock_recv(s, 512), timeout)
            except asyncio.exceptions.TimeoutError:
                raise Exception('timeout')
            return result, ID
        except Exception as error:
            if str(error) != 'timeout':
                await self.sleep((lambda x: 1 if x < 1 else x)(timeout))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(s)

    async def dns_make_doh_query(self, query, ID, address, hostname):
        server_writer = None
        try:
            server_reader, server_writer = await self.open_connection(address[0], address[1], True, hostname, 2)
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

    async def dns_clear_cache(self):
        while True:
            try:
                for x in list(self.dns_records.keys()):
                    if time.time() > self.dns_records[x][1]:
                        del self.dns_records[x]
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.sleep(10)

    def exception_handler(self, loop, context):
        pass


class yashmak_log():
    def __init__(self, config):
        self.config = config
        self.host_list = dict()
        self.log = []
        self.local_path = self.config['local_path']
        self.start_time = self.config['start_time']
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.write_log())
        self.loop.run_forever()

    def create_server(self):
        listener = socket.create_server(address=('127.0.0.1', self.config['log_port']), family=socket.AF_INET, dualstack_ipv6=False)
        return asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048)
    
    async def handler(self, client_reader, client_writer):
        try:
            host = await asyncio.wait_for(client_reader.read(65535), 20)
            if host == b'f31d7515-d90f-4eba-a4a9-8eac1d0a423e':
                await self.log_receiver(client_reader)
            else:
                raise Exception('Invalid Connection')
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(client_writer)

    async def log_receiver(self, client_reader):
        buffer = b''
        while True:
            buffer += await client_reader.read(65535)
            position = buffer.find(b'\r\n\r\n')
            data, key, instruction = buffer[:position].split(b'\r\n')
            buffer = buffer[position + 4:]
            if instruction == b'host':
                data = data.decode('utf-8')
                key = key.decode('utf-8')
                data = data[1:-1]
                data = data.replace("b'", '')
                data = data.replace("'", '')
                data = data.split(', ')
                if key not in self.host_list:
                    self.host_list[key] = set()
                for x in data:
                    self.host_list[key].add(x)
            elif instruction == b'log':
                data = data.decode('utf-8')
                data = data[1:-1]
                data = data.decode('utf-8')
                data = data.replace('"', '')
                data = data.replace('),', ')),')
                data = data.split('), ')
                for x in data:
                    self.log.append(x)
    
    async def write_host(self):
        while True:
            for x in self.host_list:
                if x != 'blacklist' and len(self.host_list[x]) > 0:
                    if os.path.exists(self.local_path + '/Cache/' + x + '.json'):
                        with open(self.local_path + '/Cache/' + x + '.json', 'r') as file:
                            data = json.load(file)
                        for y in data:
                            self.host_list[x].add(y)
                    with open(self.local_path + '/Cache/' + x + '.json', 'w') as file:
                        json.dump(list(self.host_list[x]), file)
                    self.host_list[x].clear()
            await asyncio.sleep(60)

    async def write_log(self):
        if not os.path.exists(self.local_path + '/Logs/'):
            os.makedirs(self.local_path + '/Logs/')
        while True:
            with open(self.local_path + '/Logs/' + time.strftime("%Y%m%d%H%M%S", self.start_time) + '.json', 'a+') as file:
                for x in self.log:
                    file.write(x+'\n\n')
                self.log.clear()
            await asyncio.sleep(60)

    @staticmethod
    async def clean_up(writer1=None, writer2=None):
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
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                await writer2.wait_closed()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def exception_handler(self, loop, context):
        pass


class yashmak():
    def __init__(self):
        self.load_config()
        self.load_lists()
        self.get_time()
        self.edit_iptables()

    def run_forever(self):
        # start log server
        p = multiprocessing.Process(target=yashmak_log, args=(self.config,))
        p.start()

        # start DNS server
        p = multiprocessing.Process(target=yashmak_dns, args=(self.config,))
        p.start()

        # start normal workers
        for x in range(os.cpu_count()):
            p = multiprocessing.Process(target=yashmak_worker, args=(self.config,))
            p.start()

        # start spare workers
        self.run_spares()

    def run_spares(self):
        config = self.config
        while True:
            config['ip'] = '::'
            config['port'] = self.get_calculated_port()
            ps = []
            for x in range(os.cpu_count()):
                p = multiprocessing.Process(target=yashmak_worker, args=(config, ))
                p.start()
                ps.append(p)
            while config['port'] == self.get_calculated_port():
                time.sleep(1)
            if os.popen('''systemctl list-unit-files | grep "Yashmak"''').read() == "":
                for x in ps:
                    x.kill()
            else:
                os.system("systemctl restart Yashmak")

    def get_time(self):
        client = ntplib.NTPClient()
        offset = None
        while offset == None:
            try:
                response = client.request('pool.ntp.org', version=3, timeout=1)
                offset = response.offset
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
        self.config['utc_difference'] = offset
        self.config['start_time'] = time.localtime()

    def edit_iptables(self):
        try:
            os.system("iptables -P INPUT ACCEPT")
            os.system("iptables -P OUTPUT ACCEPT")
            os.system("ip6tables -P INPUT ACCEPT")
            os.system("ip6tables -P OUTPUT ACCEPT")
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    @staticmethod
    def find_ports(exclude=None):
        ports = set()
        while len(ports) < 1:
            R = str(random.randint(2000, 8000))
            if int(R) in exclude:
                continue
            if "windows" in platform.system().lower():
                if os.popen("netstat -aon | findstr 127.0.0.1:" + R).read() == "" and os.popen("netstat -aon | findstr [::1]:" + R).read() == "":
                    ports.add(int(R))
            elif "linux" in platform.system().lower():
                if os.popen("netstat -tulpn | grep ':" + R + "'").read() == "":
                    ports.add(int(R))
        ports = list(ports)
        return ports.pop(0)

    def load_config(self):
        self.local_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        if os.path.exists(self.local_path + '/config.json'):
            with open(self.local_path + '/config.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
            self.config['uuid'] = self.UUID_detect(set(list(map(self.encode, self.config['uuid']))))
            self.config['port'] = int(self.config['port'])
            self.config['normal_dns'] = list(map(self.encode, self.config['normal_dns']))
            if 'doh_dns' in self.config:
                self.config['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
            else:
                self.config['doh_dns'] = []
            if 'proxy' in self.config:
                for x in self.config['proxy']:
                    self.config['proxy'][x]['uuid'] = self.config['proxy'][x]['uuid'].encode('utf-8')
                    self.config['proxy'][x]['port'] = int(self.config['proxy'][x]['port'])
                    self.config['proxy'][x]['host'] = self.config['proxy'][x]['host'].encode('utf-8')
            self.config['local_path'] = self.local_path
            self.config['dns_port'] = self.find_ports([self.config['port']])
            self.config['log_port'] = self.find_ports([self.config['port'], self.config['dns_port']])
        else:
            example = {'geoip_list_path': '','black_list_path': '','host_list_path': '','cert': '', 'key': '', 'uuid': [''], 'normal_dns': [''],
                       'doh_dns': [''], 'ip': '', 'port': ''}
            with open(self.local_path + '/config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_lists(self):
        self.host_list = dict()
        self.black_list = dict()
        self.proxy_list = dict()
        self.dns_records = dict()
        self.geoip_list = []

        with open(self.config['geoip_list_path'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        for x in ['10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fd00::/8','fe80::/10']:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()

        if not os.path.exists(self.local_path + '/Cache/'):
            os.makedirs(self.local_path + '/Cache/')
        for x in self.config['uuid']:
            self.host_list[x] = set()

        with open(self.config['black_list_path'], 'r') as file:
            data = json.load(file)
        for key in list(data):
            if key != 'tag':
                value = data[key].encode('utf-8')
                del data[key]
                data[key.replace('*', '').encode('utf-8')] = value
        for key in list(data['tag']):
            value = data['tag'][key].encode('utf-8')
            del data['tag'][key]
            data['tag'][key.replace('*', '').encode('utf-8')] = value
        data[None] = None
        self.black_list = data

        with open(self.config['host_list_path'], 'r') as file:
            data = json.load(file)
        for x in data:
            self.dns_records[x.encode('utf-8')] = (data[x], float('inf'))

        if 'proxy_list_path' in self.config:
            with open(self.config['proxy_list_path'], 'r') as file:
                data = json.load(file)
            for key in data:
                self.proxy_list[key] = set()
                for host in data[key]:
                    self.proxy_list[key].add(host.replace('*', '').encode('utf-8'))

        self.config['host_list'] = self.host_list
        self.config['black_list'] = self.black_list
        self.config['proxy_list'] = self.proxy_list
        self.config['geoip_list'] = self.geoip_list
        self.config['dns_records'] = self.dns_records

    @staticmethod
    def UUID_detect(UUIDs):
        for x in UUIDs:
            if len(x) != 36:
                raise Exception
        return UUIDs

    @staticmethod
    def translate(content):
        return content.replace('\\', '/')

    @staticmethod
    def encode(data):
        return data.encode('utf-8')

    @staticmethod
    def get_today():
        today = int(str(datetime.datetime.utcnow())[:10].replace('-', '')) ** 3
        return int(str(today)[today % 8:8] + str(today)[0:today % 8])

    def get_calculated_port(self):
        return 1024 + self.get_today() % 8976


if __name__ == '__main__':
    server = yashmak()
    server.run_forever()