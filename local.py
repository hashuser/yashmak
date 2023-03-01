from PyQt6 import QtWidgets, QtGui, QtCore
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
from Cryptodome.Cipher import AES
import hashlib
import shutil


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
        if isinstance(data, str):
            data = data.encode('utf-8')
            return base64.b64encode(data).decode('utf-8')
        return base64.b64encode(data)

    @staticmethod
    def base64_decode(data):
        if isinstance(data, str):
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
        if isinstance(s, str):
            s = s.encode('utf-8')
        a = base64.b64encode(s)
        rand = int.from_bytes(random.randbytes(len(a) + 1), 'little')
        b = base64.b64encode(int.to_bytes(rand + int.from_bytes(a, 'little'), len(a) + 2, 'little'))
        c = base64.b64encode(int.to_bytes(rand, len(a) + 1, 'little'))
        d = base64.b64encode(int.to_bytes(len(c), 3, 'little')) + c + b
        return base64.b64encode(d)

    @staticmethod
    def enhanced_base64_decode(s):
        if isinstance(s, str):
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

    def init_proxy_context(self):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Config/'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(self.config_path + self.config['cert'])
        return context


class ymc_connect(ymc_ssl_context):
    async def open_connection(self, host, port, TLS=False, server_hostname=None, ssl_handshake_timeout=5, timeout=5, retry=1, context=None):
        for x in range(retry):
            try:
                if TLS:
                    if context == None:
                        context = self.init_normal_context()
                    if server_hostname == None:
                        server_hostname = host
                    return await asyncio.wait_for(asyncio.open_connection(host=host, port=port, ssl=context,
                                                                          server_hostname=server_hostname,
                                                                          ssl_handshake_timeout=ssl_handshake_timeout), timeout)
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
        if isinstance(ID, bytes):
            result['ID'] = data[:2]
        else:
            result['ID'] = int.from_bytes(data[:2], 'big', signed=False)
        if result['ID'] != ID:
            return {'error': -1}
        result['flags'] = self._dns_get_flags_fast(data)
        if not result['flags']['QR']:
            return {'error': -1}
        if result['flags']['rcode'] == 3:
            return {'error': 3}
        elif result['flags']['rcode']:
            return {'error': result['flags']['rcode']}
        position = data.find(b'\xc0\x0c', 12)
        if position == -1:
            result['answers'] = []
            result['error'] = None
            return result
        raw_answer = data[position:]
        result['answers'] = self._dns_get_answers_fast(raw_answer, mq_type)
        result['error'] = None
        return result

    def _dns_decoder_debug(self, data, mq_type, ID):
        result = dict()
        if isinstance(ID, bytes):
            result['ID'] = data[:2]
        else:
            result['ID'] = int.from_bytes(data[:2], 'big', signed=False)
        if result['ID'] != ID:
            return {'error': -1}
        result['flags'] = self._dns_get_flags_debug(data)
        if not result['flags']['QR']:
            return {'error': -1}
        if result['flags']['rcode'] == 3:
            return {'error': 3}
        elif result['flags']['rcode']:
            return {'error': result['flags']['rcode']}
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
        result['answers'] = self._dns_get_answers_debug(raw_answer, mq_type)
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
                    rdata = socket.inet_ntop(socket.AF_INET, raw_answer[ps - 10:pe][12:]).encode('utf-8')
                elif q_type == 28:
                    rdata = socket.inet_ntop(socket.AF_INET6, raw_answer[ps - 10:pe][12:]).encode('utf-8')
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
                    rdata = socket.inet_ntop(socket.AF_INET, raw_answer[ps - 10:pe][12:]).encode('utf-8')
                elif q_type == 28:
                    rdata = socket.inet_ntop(socket.AF_INET6, raw_answer[ps - 10:pe][12:]).encode('utf-8')
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


class ymc_http_parser:
    @staticmethod
    async def http_get_response_body(reader):
        content = b''
        content_length, header_length = 0, 0
        while True:
            content += await asyncio.wait_for(reader.read(65535), 20)
            if not content_length:
                position = content.find(b'Content-Length: ')
                if position >= 0:
                    content_length = int(content[position + 16:content.find(b'\r\n', position + 16)])
            if not header_length:
                position = content.find(b'\r\n\r\n')
                if position >= 0:
                    header_length = position + 4
            if len(content) - header_length >= content_length:
                if content.find(b'Content-Encoding: gzip\r\n') >= 0:
                    return gzip.decompress(content[header_length:])
                else:
                    return content[header_length:]

    @staticmethod
    def http_make_request_header(method, URL, user_agent=None):
        if isinstance(method, str):
            method = method.encode('utf-8')
        if isinstance(URL, str):
            URL = URL.encode('utf-8')
        if user_agent == None:
            user_agent = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39"
        elif isinstance(user_agent, str):
            user_agent = user_agent.encode('utf-8')
        start = URL.find(b'://')+3
        end = URL.find(b'/',start)
        address = URL[start:end]
        URL = URL[end:]
        header = method + b" " + URL + b" HTTP/1.1\r\nHost: " + address + b"\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip\r\nUser-Agent: " + user_agent + b"\r\n\r\n"
        return header

    def http_get_address_from_URL(self, URL):
        if isinstance(URL, str):
            URL = URL.encode('utf-8')
        start = URL.find(b'://')+3
        end = URL.find(b'/',start)
        address = URL[start:end]
        if b'https' in URL[:5]:
            return self.http_separate_address(address, port=b'443')
        else:
            return self.http_separate_address(address, port=b'80')

    @staticmethod
    def http_separate_address(address,host=None,port=None):
        if address[0] == 91:
            offset = address.find(b']')
            host = address[1:offset]
            offset += 2
            if offset < len(address):
                port = address[offset:]
        else:
            offset = address.find(b':')
            if offset >= 0:
                host = address[:offset]
                port = address[offset + 1:]
            else:
                host = address
        return host, port

    @staticmethod
    def http_get_request_type(data):
        data_3, data_4 = data[:3], data[:4]
        if data[:7] == b'CONNECT':
            request_type = 0
            offset = 8
        elif data_3 == b'GET':
            request_type = 1
            offset = 4
        elif data_4 == b'POST':
            request_type = 2
            offset = 5
        elif data_3 == b'PUT':
            request_type = 3
            offset = 4
        elif data_4 == b'HEAD':
            request_type = 4
            offset = 5
        else:
            request_type = 5
            offset = 0
        return request_type, offset

    def http_get_address_NG(self, data, request_type, offset, get_url=True):
        if not request_type:
            host, port, URL = None, b'443', None
        else:
            host, port, URL = None, b'80', None
        if data[offset] == 47:
            offset = data.find(b'\r\nHost: ', offset) + 8
            segment = data[offset:data.find(b'\r\n', offset)]
        else:
            segment = data[offset:data.find(b' ', offset)]
            if request_type:
                if segment[0] == 104 and get_url:
                    URL = b'https' + segment[4:]
                segment = segment[7:segment.find(b'/', 7)]
        host, port = self.http_separate_address(segment,port=port)
        return URL, host, port

    @staticmethod
    def http_filter_request_header(data, offset):
        if data[offset] != 47:
            data = data.replace(b'http://', b'', 1)
            data = data[:data.find(b' ') + 1] + data[data.find(b'/', 7):]
        data = data.replace(b'Proxy-', b'', 1)
        return data


class ymc_dns_cache(ymc_base, ymc_connect):
    def __init__(self):
        self.dns_records, self.dns_futures_map = dict(), dict()
        self.dns_query_send_buffer = asyncio.queues.Queue()

    async def connect_dns_local(self):
        if socket.has_dualstack_ipv6():
            localhost = '::1'
        else:
            localhost = '127.0.0.1'
        self.dns_local_reader, self.dns_local_writer = await self.open_connection(localhost, self.config['dns_port'])
        self.dns_local_writer.write(b'8f1f5d11-98bc-42de-a996-e86c8c0cdf7f')
        await self.dns_local_writer.drain()
        self.loop.create_task(self.dns_query_sender())
        self.loop.create_task(self.dns_response_receiver())

    async def resolve(self, host, force=False):
        if self.is_ip(host):
            host = host.replace(b'::ffff:', b'')
            return [host]
        elif not force and host in self.dns_records:
            age = time.time() - self.dns_records[host][1]
            if 0 < age <= 600:
                self.loop.create_task(self.dns_query(host))
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
        future = self.loop.create_future()
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

    async def connect_proxy_server(self):
        server_reader, server_writer = None, None
        if self.main_port_fail <= 100:
            ports = [self.config['port'], self.get_calculated_port()]
        else:
            ports = [self.get_calculated_port()]
        for port in ports:
            for IP in await self.resolve(self.config['host']):
                try:
                    server_reader, server_writer = await self.open_connection(IP, port, True, self.config['host'],context=self.proxy_context)
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


class ymc_client_updater(ymc_base, ymc_http_parser, ymc_connect):
    async def http_fetch(self, URL, mode='GET', retry=3):
        server_reader, server_writer = None, None
        for x in range(retry):
            try:
                host, port = self.http_get_address_from_URL(URL)
                server_reader, server_writer = await self.open_connection(host, port, True, retry=3)
                server_writer.write(self.http_make_request_header(mode, URL))
                await server_writer.drain()
                data = await self.http_get_response_body(server_reader)
                return data
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
            finally:
                await self.clean_up(server_writer)

    async def download_file(self, dic, x, URL):
        base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        if os.path.exists(base_path + '/Files/' + str(x)):
            with open(base_path + '/Files/' + str(x), 'rb') as file:
                container = hashlib.sha256(file.read())
                if dic['hashtable'][str(x)] == container.hexdigest():
                    return 0
        with open(base_path + '/Files/' + str(x), 'wb') as file:
            file.write(await self.http_fetch(URL + str(x)))
            file.flush()
        self.download_counter -= 1

    @staticmethod
    def load_files():
        base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        file_names = list(map(int, os.listdir(base_path + '/Files')))
        file_names.sort()
        content = b''
        for x in file_names:
            with open(base_path + '/Files/' + str(x), 'rb') as file:
                content += file.read()
        return content

    @staticmethod
    def AES_decrypt(s, tag, key, nonce):
        cipher = AES.new(key=key, mode=AES.MODE_GCM,nonce=nonce, mac_len=16)
        return cipher.decrypt_and_verify(s, tag)

    async def update_yashmak(self):
        try:
            base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
            with open(base_path + '/Config/update.json', 'rb') as file:
                update_config = json.loads(file.read())
            URL = self.enhanced_base64_decode(update_config['URL']).decode('utf-8')
            key = self.enhanced_base64_decode(update_config['key'])
            nonce = self.enhanced_base64_decode(update_config['nonce'])
            info = json.loads(await self.http_fetch(URL+'info.json'))
            try:
                with open(base_path + '/Config/config.json', 'rb') as file:
                    now = json.loads(file.read())
            except Exception as error:
                now = {'version': '-1'}
            if int(info['version']) > int(now['version']):
                os.makedirs(base_path + '/Files', exist_ok=True)
                self.download_counter = 0
                for x in info['files']:
                    while self.download_counter >= 10:
                        await self.sleep(1)
                    self.loop.create_task(self.download_file(info, x, URL))
                    self.download_counter += 1
                while self.download_counter > 0:
                    await self.sleep(1)
                content = self.load_files()
                content = self.AES_decrypt(content[:-16], content[-16:], key, nonce)
                with open(base_path + '/Updater.exe', 'wb') as file:
                    file.write(content)
                    file.flush()
                shutil.rmtree(base_path + '/Files',ignore_errors=True)
                with open(base_path + '/Config/new.json', 'w') as file:
                    file.write(info['version'])
                    file.flush()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None


class yashmak_core(ymc_connect_remote_server, ymc_http_parser):
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
        self.loop.create_task(self.connect_dns_local())
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
            await self.redirect(sock, host, URL, request_type)
            await self.proxy(host, port, request_type, data, sock, self.is_abroad(host))
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(sock)

    async def make_switches(self, sock, sr, sw, request_type):
        if request_type == 1 or request_type == 2:
            scan = True
        else:
            scan = False
        return [asyncio.create_task(self.switch_up(sock, sw, scan)), asyncio.create_task(self.switch_down(sr,sock))]

    async def switch_down(self, reader, writer):
        try:
            while True:
                data = await reader.read(65535)
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
                    request_type, offset = self.http_get_request_type(data)
                    if 0 < request_type < 5:
                        URL, host, _ = self.http_get_address_NG(data, request_type, offset)
                        if not await self.redirect(reader,host,URL,request_type):
                            data = self.http_filter_request_header(data, offset)
                        else:
                            continue
                writer.write(data)
                await writer.drain()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(writer)

    async def redirect(self, sock, host, URL, request_type):
        if URL and request_type and self.host_in_it(host, self.HSTS_list) and not self.URL_in_it(URL, self.EXURL_list):
            if request_type == 1:
                await self.http_response(sock, 301, URL)
            else:
                await self.http_response(sock, 307, URL)
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

    async def make_proxy(self, host, port, data, request_type, abroad, sock):
        server_reader, server_writer = None, None
        if not abroad:
            IPs = await self.get_IPs(host)
            for x in range(len(IPs)):
                address = IPs[int(random.random() * 1000000 % len(IPs))]
                if self.config['mode'] == 'auto' and not (self.is_china_ip(address) or self.is_local_ip(address)):
                    abroad = True
                    break
                elif address not in [b'127.0.0.1', b'::1']:
                    try:
                        server_reader, server_writer = await self.open_connection(address,port)
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
            await self.get_IPs(host, force=True)
            raise Exception('Fail to connect remote server')
        return server_reader, server_writer

    async def get_IPs(self, host, force=False):
        try:
            return await self.resolve(host, force)
        except Exception:
            return []

    async def do_handshake(self, host, port):
        if len(self.connection_pool) == 0:
            server_reader, server_writer = await self.connect_proxy_server()
            server_writer.write(self.config['uuid'])
        else:
            server_reader, server_writer = self.connection_pool.pop(-1)
            self.pool_future.set_result(True)
        server_writer.write(int.to_bytes(len(host + b'\n' + port + b'\n'), 2, 'big', signed=True) + host + b'\n' + port + b'\n')
        await server_writer.drain()
        return server_reader, server_writer

    async def http_response(self, sock, code, URL=None):
        if code == 200:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 200 Connection Established\r\n\r\n''')
        elif code == 301:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\n\r\n''')
        elif code == 307:
            await self.loop.sock_sendall(sock, b'''HTTP/1.1 307 Temporary Redirect\r\nLocation: ''' + URL + b'''\r\n\r\n''')
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
            self.pool_future = None
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
            if len(self.connection_pool):
                self.pool_future = self.loop.create_future()
                await self.pool_future
            else:
                await self.sleep(1)

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
            await self.sleep(1)
            self.pool_future.set_result(True)

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
            self.pool_future.set_result(True)
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
        request_type, offset = self.http_get_request_type(data)
        if request_type == 5:
            host, port = await self.socks5_get_address(sock)
            URL, data = None, None
        elif request_type == 0:
            URL, host, port = self.http_get_address_NG(data, request_type, offset)
            data = None
        else:
            URL, host, port = self.http_get_address_NG(data, request_type, offset)
            data = self.http_filter_request_header(data, offset)
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
            if data[:4] == b'www.':
                return data[4:]
            return data[data.find(b'.'):]
        else:
            return data

    def is_china_ip(self, ip):
        return self.ip_in_it(ip, self.geoip_list)

    def is_local_ip(self, ip):
        return self.ip_in_it(ip, self.local_ip_list)

    def exception_handler(self, loop, context):
        pass


class yashmak_dns(ymc_base, ymc_dns_parser, ymc_connect):
    def __init__(self, config, response):
        try:
            #print(os.getpid(),'dns')
            super().__init__()
            self.init(config, response)
        except Exception as error:
            response.put("yashmak_dns:"+str(error))
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def init(self, config, response):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.normal_context = self.init_normal_context()
        self.dns_records, self.dns_futures_map = dict(), dict()
        self.ipv4, self.ipv6 = None, None
        self.set_priority('above_normal')
        response.put('OK')
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
            sock = client_writer.get_extra_info('socket')
            host = await asyncio.wait_for(client_reader.read(65535), 20)
            if host == b'8f1f5d11-98bc-42de-a996-e86c8c0cdf7f':
                dns_response_send_buffer = asyncio.queues.Queue()
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

    async def network_detector(self, hosts, dns_server):
        for host in hosts:
            ipv4, ipv6 = await asyncio.gather(self.dns_query_worker(host, 'A', False, dns_server, 0.5), self.dns_query_worker(host, 'AAAA', False, dns_server, 0.5))
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

    async def resolve(self, q_type, host, doh=False):
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

    async def dns_query(self, host, doh):
        future = self.loop.create_future()
        if host in self.dns_futures_map:
            self.dns_futures_map[host].add(future)
        else:
            self.dns_futures_map[host] = {future}
        if len(self.dns_futures_map[host]) == 1:
            self.loop.create_task(self.dns_query_manager(host, doh))
        await future

    async def dns_query_manager(self, host, doh):
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

    async def dns_query_worker(self, host, q_type, doh, dns_server=None, timeout=5.0):
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


class yashmak_log(ymc_connect_remote_server):
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
        self.loop.create_task(self.connect_dns_local())
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
                    # print(sock.getpeername()[0], sock.getsockname()[1], type(sock.getpeername()[0]), type(sock.getsockname()[1]))
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


class yashmak_daemon(ymc_internet_status_cache, ymc_client_updater):
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
            self.config['servers'][self.config['active']]['startup'] = self.preference['startup']
            self.config['servers'][self.config['active']]['mode'] = self.preference['mode']
            self.config['servers'][self.config['active']]['white_list_path'] = self.config_path + self.config['white_list']
            self.config['servers'][self.config['active']]['black_list_path'] = self.config_path + self.config['black_list']
            self.config['servers'][self.config['active']]['HSTS_list_path'] = self.config_path + self.config['HSTS_list']
            self.config['servers'][self.config['active']]['EXURL_list_path'] = self.config_path + self.config['EXURL_list']
            self.config['servers'][self.config['active']]['geoip_list_path'] = self.config_path + self.config['geoip_list']
            self.config['servers'][self.config['active']]['normal_dns'] = list(map(self.encode, self.config['normal_dns']))
            self.config['servers'][self.config['active']]['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
            self.config['servers'][self.config['active']]['worker'] = (lambda x: os.cpu_count() if x > os.cpu_count() else x)(int(self.config['worker']))
            self.config = self.config['servers'][self.config['active']]
            self.config['host'] = self.enhanced_base64_decode(self.config['host'])
            self.config['port'] = self.enhanced_base64_decode(self.config['port'])
            self.config['uuid'] = self.enhanced_base64_decode(self.config['uuid'])
            self.config['listen'] = int(self.config['listen'])
        else:
            example = {'version': '', 'startup': '', 'mode': '', 'active': '', 'white_list': '', 'black_list': '',
                       'HSTS_list': '', 'EXURL_list': '', 'geoip_list': '', 'normal_dns': [''], 'doh_dns': [''],
                       'worker': '', 'servers': {'US-01': {'cert': '', 'host': '', 'port': '', 'uuid': '', 'listen': ''}}}
            with open(self.config_path + 'config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_exception_list(self):
        def load_list(location, var, funcs, replace):
            if location and not os.path.exists(location):
                with open(location, 'w') as file:
                    json.dump([], file)
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
            self.geoip_list.append([int(network[0]), int(network[-1])])
        for x in ['10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fd00::/8', 'fe80::/10']:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]), int(network[-1])])
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
            R = str(random.randint(2000, 8000))
            if os.popen("netstat -aon | findstr 127.0.0.1:" + R).read() == "" and os.popen("netstat -aon | findstr [::1]:" + R).read() == "":
                ports.add(int(R))
        ports = list(ports)
        self.config['dns_port'] = ports.pop(0)

    def write_pid(self):
        with open(self.config_path + 'pid', 'w') as file:
            file.write(str(os.getpid()))
            file.flush()

    async def yashmak_updater(self):
        S = 0
        while True:
            if time.time() - S > 3600:
                while not self.has_internet():
                    await self.sleep(1)
                await self.update_yashmak()
                S = time.time()
            await self.sleep(300)

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
        self.response.put('Child Process Accidentally Exit')
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
        while True:
            if self.has_internet() is True:
                self.response.put('OK')
            elif self.has_internet() is False:
                self.response.put('No internet connection')
            await self.sleep(1)

    async def suicide(self):
        await self.loop.shutdown_asyncgens()
        while True:
            os.kill(os.getpid(), signal.SIGTERM)

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
        self.init_GUI()

    @staticmethod
    def get_real(screen_size):
        hDC = win32gui.GetDC(0)
        wr = win32print.GetDeviceCaps(hDC, win32con.DESKTOPHORZRES)
        hr = win32print.GetDeviceCaps(hDC, win32con.DESKTOPVERTRES)
        w = screen_size.width()
        h = screen_size.height()
        return w / wr, h / hr

    def activate(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.ActivationReason.Context:
            position = win32api.GetCursorPos()
            self.tray_menu_main.popup(QtCore.QPoint(int(position[0]*self.real[0]), int(position[1]*self.real[1])))
        elif reason == QtWidgets.QSystemTrayIcon.ActivationReason.Trigger:
            if time.time() - self.developer[1] > 3:
                self.developer = (0, time.time())
            self.developer = (self.developer[0] + 1, time.time())
            if self.developer[0] >= 5:
                os.popen("start " + self.base_path + "/Config")
                self.developer = (0, time.time())

    def close_menu(self):
        self.tray_menu_main.close()

    def init_GUI(self):
        try:
            self.init_constants()
            self.init_config_and_preference()
            self.init_widget()
            self.run(is_restart=False)
        except Exception as error:
            self.panic(error)

    def init_constants(self):
        self.base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.path_config = self.base_path + '/Config/config.json'
        self.path_preference = self.base_path + '/Config/preference.json'
        self.INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
        self.ENVIRONMENT_SETTING = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_ALL_ACCESS)

    def init_config_and_preference(self):
        preference = {'startup': 'auto', 'mode': 'auto', 'proxy': 'normal'}
        if os.path.exists(self.path_preference):
            with open(self.path_preference, 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.preference = json.loads(content)
            for x in preference:
                if x not in self.preference:
                    self.preference[x] = preference[x]
        else:
            self.preference = preference
        with open(self.path_preference, 'w') as file:
            json.dump(self.preference, file, indent=4)
        if os.path.exists(self.path_config):
            with open(self.path_config, 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
        else:
            raise Exception

    def init_SystemTray_and_menu(self):
        self.SystemTray = QtWidgets.QSystemTrayIcon()
        self.set_theme()
        self.SystemTray.activated.connect(self.activate)
        # init System-tray
        self.tray_menu_main = QtWidgets.QMenu()
        self.tray_menu_sub = QtWidgets.QMenu()
        self.set_actions()
        self.set_QSS()
        self.set_flags()
        # init Tray-menu
        self.init_menu_elements()

    def init_widget(self):
        self.widget_main = QtWidgets.QWidget()
        self.widget_main.hide()
        self.init_SystemTray_and_menu()
        self.show_SystemTray()

    def init_menu_elements(self):
        try:
            ver = self.config['version']
            if len(ver) == 3:
                self.SystemTray.setToolTip('Yashmak v' + ver[0] + '.' + ver[1] + '.' + ver[2])
            elif len(ver) == 4:
                self.SystemTray.setToolTip('Yashmak v' + ver[:2] + '.' + ver[2] + '.' + ver[3])
            else:
                raise Exception('Illegal Version')
            self.set_mode_UI(self.preference['mode'].lower())
            if self.preference['startup'].lower() == 'auto':
                self.set_auto_startup(True)
                self.actions['main']['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
            elif self.preference['startup'].lower() == 'manual':
                self.set_auto_startup(False)
                self.actions['main']['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
            if self.preference['proxy'].lower() == 'enhanced':
                self.set_enhanced_proxy(True)
                self.actions['main']['EnhancedProxy'].setIcon(QtGui.QIcon('correct.svg'))
            elif self.preference['proxy'].lower() == 'normal':
                self.set_enhanced_proxy(False)
                self.actions['main']['EnhancedProxy'].setIcon(QtGui.QIcon('hook.svg'))
        except KeyError as error:
            raise Exception('配置文件错误 ' + str(error))
        self.init_menu()

    def show_SystemTray(self):
        self.SystemTray.show()

    def close_SystemTray(self):
        self.SystemTray.hide()
        self.widget_main.deleteLater()
        self.widget_main.close()

    def set_theme(self):
        if self.is_light_Theme():
            self.SystemTray.setIcon(QtGui.QIcon('light_mode_icon.svg'))
        else:
            self.SystemTray.setIcon(QtGui.QIcon('dark_mode_icon.svg'))

    def set_actions(self):
        self.actions = {
            'main': {
                'auto': QtGui.QAction(self.text_translator(' 自动模式 '), triggered=lambda: self.react('auto')),
                'global': QtGui.QAction(self.text_translator(' 全局模式 '), triggered=lambda: self.react('global')),
                'direct': QtGui.QAction(self.text_translator(' 直连模式 '), triggered=lambda: self.react('direct')),
                'AutoStartup': QtGui.QAction(self.text_translator(' 开机自启 '), triggered=lambda: self.react('AutoStartup')),
                'EnhancedProxy': QtGui.QAction(self.text_translator(' 增强代理 '), triggered=lambda: self.react('EnhancedProxy')),
                'AllowUWP': QtGui.QAction(self.text_translator(' 允许UWP '), triggered=lambda: self.react('AllowUWP')),
                'Close': QtGui.QAction(self.text_translator(' 退出 '), triggered=lambda: self.react('Close'))
            },
            'sub': {},
            'settings': QtGui.QAction(self.text_translator(' 设置 '))
        }
        for x in self.config['servers'].keys():
            self.actions['sub'][x] = QtGui.QAction(' ' + x + ' ')

    def set_QSS(self):
        if self.language == 'zh-CN':
            font_family = 'Microsoft Yahei'
        else:
            font_family = 'Arial'
        style_sheet = '''QMenu {background-color:#ffffff; font-size:10pt; font-family:''' + font_family + '''; color: #333333; border:2px solid #eeeeee; border-radius: 6px;}
                                           QMenu::item:selected {background-color:#eeeeee; color:#333333; padding:8px 10px 8px 10px; border:2px solid #eeeeee; border-radius:4;}
                                           QMenu::item {background-color:#ffffff;padding:8px 10px 8px 10px; border:2px solid #ffffff; border-radius:4;}
                                           QMenu::icon {padding:8px 6px 8px 6px;}'''
        self.tray_menu_main.setStyleSheet(style_sheet)
        self.tray_menu_sub.setStyleSheet(style_sheet)

    def set_flags(self):
        self.tray_menu_main.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.tray_menu_main.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        self.tray_menu_main.setWindowFlag(QtCore.Qt.WindowType.NoDropShadowWindowHint)
        self.tray_menu_sub.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.tray_menu_sub.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        self.tray_menu_sub.setWindowFlag(QtCore.Qt.WindowType.NoDropShadowWindowHint)

    def react(self, message):
        if isinstance(message, QtGui.QAction):
            message = message.text()[1:-1]
            if message not in ['设置', 'Settings']:
                self.change_active_server(message)
            else:
                self.open_widget()
        if message in ['auto', 'global', 'direct']:
            self.change_mode_to(message)
        elif message == 'Close':
            self.exit()
            self.pop_message('已退出并断开连接')
            time.sleep(2)
            self.close_SystemTray()
            raise Exception('EXIT')
        elif message == 'AutoStartup':
            self.change_startup_policy()
        elif message == 'EnhancedProxy':
            self.change_enhanced_proxy_policy()
        elif message == 'AllowUWP':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 0)
            self.pop_message('已允许UWP应用连接代理')
        self.tray_menu_main.update()
        self.tray_menu_sub.update()

    def open_widget(self):
        pass

    def change_mode_to(self, mode):
        mes = {'auto': '已设置为自动模式', 'global': '已设置为全局模式', 'direct': '已设置为直连模式'}
        self.kill_daemon()
        self.edit_preference('mode', mode.lower())
        self.run(is_restart=True)
        self.pop_message(mes[mode])
        self.set_mode_UI(mode)

    def change_startup_policy(self):
        reverse = {'auto': 'manual', 'manual': 'auto'}
        self.edit_preference('startup', reverse[self.preference['startup'].lower()])
        if self.preference['startup'].lower() == 'auto':
            self.set_auto_startup(True)
            self.actions['main']['AutoStartup'].setIcon(QtGui.QIcon('correct.svg'))
            self.pop_message('已设置开机自启')
        elif self.preference['startup'].lower() == 'manual':
            self.set_auto_startup(False)
            self.actions['main']['AutoStartup'].setIcon(QtGui.QIcon('hook.svg'))
            self.pop_message('已取消开机自启')

    def change_enhanced_proxy_policy(self):
        reverse = {'normal': 'enhanced', 'enhanced': 'normal'}
        self.edit_preference('proxy', reverse[self.preference['proxy'].lower()])
        if self.preference['proxy'].lower() == 'enhanced':
            self.set_enhanced_proxy(True)
            self.actions['main']['EnhancedProxy'].setIcon(QtGui.QIcon('correct.svg'))
            self.pop_message('已开启增强代理')
        elif self.preference['proxy'].lower() == 'normal':
            self.set_enhanced_proxy(False)
            self.actions['main']['EnhancedProxy'].setIcon(QtGui.QIcon('hook.svg'))
            self.pop_message('已关闭增强代理')

    def change_active_server(self, server):
        self.kill_daemon()
        self.edit_config('active', server)
        self.tray_menu_sub.clear()
        for x in self.actions['sub']:
            if x != self.config['active']:
                self.tray_menu_sub.addAction(self.actions['sub'][x])
        self.tray_menu_sub.addAction(self.actions['settings'])
        self.tray_menu_sub.setIcon(QtGui.QIcon('correct.svg'))
        self.tray_menu_sub.setTitle(' ' + self.config['active'] + ' ')
        self.run(is_restart=True)
        self.pop_message(self.text_translator('服务器已设置为') + server, translate=False)

    def edit_preference(self, key, value):
        if os.path.exists(self.path_preference):
            with open(self.path_preference, 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.preference = json.loads(content)
        else:
            raise Exception
        self.preference[key] = value
        with open(self.path_preference, 'w') as file:
            json.dump(self.preference, file, indent=4)

    def edit_config(self, key, value):
        if os.path.exists(self.path_config):
            with open(self.path_config, 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
        else:
            raise Exception
        self.config[key] = value
        with open(self.path_config, 'w') as file:
            json.dump(self.config, file, indent=4)

    def option_switcher(self, items, target):
        for x in items:
            if x == target:
                self.actions['main'][x].setIcon(QtGui.QIcon('correct.svg'))
            else:
                self.actions['main'][x].setIcon(QtGui.QIcon('hook.svg'))

    def set_mode_UI(self, mode):
        self.option_switcher(['auto', 'global', 'direct'], mode)

    def init_menu(self):
        item = ['auto', 'global', 'direct', 'Separator', 'AutoStartup', 'EnhancedProxy', 'AllowUWP', 'Close']
        for x in item:
            if x == 'Separator':
                self.tray_menu_main.addMenu(self.tray_menu_sub)
                self.tray_menu_main.addSeparator()
            elif x in self.actions['main']:
                self.tray_menu_main.addAction(self.actions['main'][x])
        for x in self.actions['sub']:
            if x != self.config['active']:
                self.tray_menu_sub.addAction(self.actions['sub'][x])
        self.tray_menu_sub.addAction(self.actions['settings'])
        self.tray_menu_sub.setIcon(QtGui.QIcon('correct.svg'))
        self.tray_menu_sub.setTitle(' ' + self.config['active'] + ' ')
        self.tray_menu_sub.triggered.connect(self.react)

    def set_proxy(self, enable):
        platform = sys.platform
        if platform == 'win32':
            if enable:
                self.set_key(self.INTERNET_SETTINGS, 'ProxyEnable', 1)
                self.set_key(self.INTERNET_SETTINGS, 'ProxyOverride', "localhost;192.168.1.1;<local>")
                self.set_key(self.INTERNET_SETTINGS, 'ProxyServer','127.0.0.1:' + self.config['servers'][self.config['active']]['listen'])
                self.set_key(self.ENVIRONMENT_SETTING, 'HTTP_PROXY','http://127.0.0.1:' + self.config['servers'][self.config['active']]['listen'])
                self.set_key(self.ENVIRONMENT_SETTING, 'HTTPS_PROXY','http://127.0.0.1:' + self.config['servers'][self.config['active']]['listen'])
            else:
                self.set_key(self.INTERNET_SETTINGS, 'ProxyEnable', 0)
                self.delete_key(self.ENVIRONMENT_SETTING, 'HTTP_PROXY')
                self.delete_key(self.ENVIRONMENT_SETTING, 'HTTPS_PROXY')
            internet_set_option = ctypes.windll.wininet.InternetSetOptionW
            internet_set_option(0, 37, 0, 0)
            internet_set_option(0, 39, 0, 0)
        else:
            raise Exception('Unsupported Platform')

    @staticmethod
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
                raise Exception('Invalid Value')
            winreg.SetValueEx(root, name, 0, reg_type, value)

    @staticmethod
    def delete_key(root, name):
        try:
            winreg.DeleteValue(root, name)
        except Exception:
            pass

    def set_auto_startup(self, enable):
        startup_path = "C:/Users/" + os.getlogin() + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
        for x in os.listdir(startup_path):
            if os.path.isfile(startup_path+x) and "Yashmak" in x:
                try:
                    os.remove(startup_path+x)
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
        location = startup_path + "Yashmak" + str(random.randint(10000000,99999999)) + ".lnk"
        if enable:
            self.make_link(location, self.base_path + "\Verify.exe")
        else:
            self.make_link(location, self.base_path + "\Recover.exe")

    def set_enhanced_proxy(self, enable):
        if enable:
            win32api.ShellExecute(0, 'open', self.base_path + '\Proxifier\Proxifier.exe',self.base_path + '\Proxifier\Profiles\Yashmak.ppx silent-load', '', 1)
        else:
            for x in psutil.pids():
                try:
                    if 'proxifier.exe' == psutil.Process(x).name().lower():
                        psutil.Process(x).kill()
                        break
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None

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
            USER_PROFILE = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Control Panel\Desktop\MuiCached', 0,winreg.KEY_ALL_ACCESS)
            value, _ = winreg.QueryValueEx(USER_PROFILE, 'MachinePreferredUILanguages')
            return value
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            return None

    def kill_daemon(self):
        try:
            self.response.put('kill')
            while self.main_process.is_alive():
                self.command.put('kill')
                time.sleep(0.2)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    def exit(self):
        self.set_proxy(False)
        self.set_enhanced_proxy(False)
        self.kill_daemon()

    def run(self, is_restart=False):
        repaired = 0
        spares = ['chinalist.json', 'old.json']
        while True:
            path = self.base_path + '/Config/pid'
            try:
                if os.path.exists(path):
                    with open(path, 'r') as file:
                        pid = int(file.read())
                    if pid in psutil.pids() and psutil.Process(pid).name().lower() == 'yashmak.exe':
                        raise Exception('Yashmak has already lunched')
            except Exception as error:
                if 'Yashmak has already lunched' in str(error):
                    raise Exception('Yashmak has already lunched')
            self.command, self.response = aioprocessing.AioQueue(), aioprocessing.AioQueue()
            self.main_process = aioprocessing.AioProcess(target=yashmak_daemon, args=(self.command,self.response,))
            self.main_process.start()
            info = self.response.get()
            if 'yashmak_daemon:' in info and repaired <= 1:
                self.repair(spares[repaired])
                repaired += 1
            else:
                T = threading.Thread(target=self.daemon_thread, args=(is_restart, info,))
                T.start()
                break

    def daemon_thread(self, restart, info):
        if info == 'OK':
            self.set_proxy(True)
            connected = True
            if not restart:
                self.message_successful()
        else:
            connected = False
        while True:
            if info == 'kill':
                break
            elif info == 'OK':
                if not connected:
                    connected = True
                    self.pop_message('连接已恢复')
            elif info == 'No internet connection':
                if connected:
                    connected = False
                    self.pop_message('连接已中断')
            else:
                self.panic(Exception(info))
                break
            time.sleep(0.2)
            info = self.response.get()

    def message_successful(self):
        if os.path.exists(self.base_path + '/Config/new.json'):
            self.pop_message('Yashmak更新成功')
            os.remove(self.base_path + '/Config/new.json')
        else:
            self.pop_message('网络代理已启动')

    def panic(self, error):
        self.panic_log(str(error))
        if 'Yashmak has already lunched' in str(error) or 'yashmak_load_balancer:' in str(error):
            self.kill_daemon()
            self.pop_message('检测到运行中的Yashmak')
        elif 'yashmak_daemon:' in str(error):
            # self.exit()
            self.pop_message('配置文件错误')
            return True
        elif 'Child Process Accidentally Exit' in str(error):
            self.exit()
            self.pop_message('子进程意外退出')
        elif str(error) != 'EXIT':
            self.exit()
            self.pop_message('未知错误')
        time.sleep(5)
        self.close_SystemTray()
        while True:
            os.kill(os.getpid(), signal.SIGTERM)

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

    def text_translator(self, message):
        translations = {'网络代理已启动': 'Proxy started',
                        '连接已恢复': 'Connection restored',
                        '连接已中断': 'Connection terminated',
                        'Yashmak更新成功': 'Yashmak successfully updated',
                        '未知错误': 'Unknown Error',
                        '子进程意外退出': 'Child Process Accidentally Exit',
                        '配置文件错误': 'Config Error',
                        '检测到运行中的Yashmak': 'Running Yashmak has detected',
                        '已允许UWP应用连接代理': 'UWP apps have been allowed to connect to the proxy',
                        '已开启增强代理': 'Enhanced Proxy has been enabled', '已关闭增强代理': 'Enhanced-proxy has been disabled',
                        '已设置开机自启': 'Auto-startup has been enabled', '已取消开机自启': 'Auto-startup has been disabled',
                        '已退出并断开连接': 'Exited and disconnected', '已设置为直连模式': 'Has set to Direct Mode',
                        '已设置为全局模式': 'Has set to Global Mode', '已设置为自动模式': 'Has set to Auto Mode',
                        '服务器已设置为': 'Server has set to ', ' 自动模式 ': ' Auto Mode', ' 全局模式 ': ' Global Mode',
                        ' 直连模式 ': ' Direct Mode', ' 开机自启 ': ' Auto Startup', ' 增强代理 ': ' Enhanced Proxy ',
                        ' 允许UWP ': ' Allow UWP', ' 服务器 ': ' Servers ', ' 退出 ': ' Exit', ' 设置 ': ' Settings '}
        if self.language == 'zh-CN':
            return message
        elif message in translations:
            return translations[message]
        else:
            return 'ERROR'

    def pop_message(self, message, translate=True):
        if translate:
            self.SystemTray.showMessage('Yashmak', self.text_translator(message), msecs=1000)
        else:
            self.SystemTray.showMessage('Yashmak', message, msecs=1000)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('windowsvista')
    GUI = yashmak_GUI(app.screens()[0].size())
    sys.exit(app.exec())
