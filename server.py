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

gc.set_threshold(100000, 50, 50)
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


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


class yashmak_worker(ymc_dns_parser):
    def __init__(self,config,host_list,dns_pool,dns_ttl,geoip_list,exception_list_name,local_path,utc_difference,start_time):
        self.config = config
        self.normal_context = self.get_normal_context()
        self.host_list = host_list
        self.geoip_list = geoip_list
        self.dns_pool = dns_pool
        self.dns_ttl = dns_ttl
        self.exception_list_name = exception_list_name
        self.local_path = local_path
        self.utc_difference = utc_difference
        self.start_time = start_time
        self.ipv4 = True
        self.ipv6 = True
        self.log = []
        self.set_priority()
        self.create_loop()

    def create_server(self):
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET6,
                                            reuse_port=True,dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET,
                                            reuse_port=True,dualstack_ipv6=False)
        return asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048,ssl=self.get_proxy_context())

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(self.create_server())
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.write_log())
        self.loop.create_task(self.updater_cache())
        self.loop.create_task(self.clear_cache())
        self.loop.create_task(self.ipv4_test())
        self.loop.create_task(self.ipv6_test())
        self.loop.run_forever()

    @staticmethod
    def set_priority():
        p = psutil.Process(os.getpid())
        p.nice(-10)

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
            while 1:
                data = int.from_bytes((await asyncio.wait_for(client_reader.readexactly(2),20)), 'big',signed=True)
                if data == 0:
                    continue
                elif data > 0:
                    data = await asyncio.wait_for(client_reader.readexactly(data),20)
                    host, port = self.process(data)
                    await self.redirect(client_writer, host)
                    await self.proxy(host,port,uuid,client_reader,client_writer)
                elif data == -4:
                    await self.echo(client_writer)
                elif data == -2:
                    await self.TCP_ping(client_writer, client_reader)
                elif data == -3:
                    await self.updater(client_writer, uuid)
                else:
                    raise Exception('unknown command')
        except Exception as error:
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
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    async def make_proxy(self,host,port,uuid):
        server_reader, server_writer = None, None
        IPs = await self.get_IPs(host)
        IPs_length = len(IPs)
        for x in range(IPs_length):
            address = IPs[int(random.random() * 1000 % IPs_length)]
            self.is_china_ip(address, host, uuid)
            server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port), 5)
            break
        if server_reader == None or server_writer == None:
            raise Exception
        return server_reader,server_writer

    async def make_switches(self,cr,cw,sr,sw):
        return [asyncio.create_task(self.switch(cr,sw)),asyncio.create_task(self.switch(sr,cw))]

    async def get_IPs(self,host):
        if self.ipv4 and self.ipv6:
            IPs = await self.resolve('ALL', host)
        elif self.ipv4:
            IPs = await self.resolve('A', host)
        elif self.ipv6:
            IPs = await self.resolve('AAAA', host)
        else:
            raise Exception('No IP Error')
        if IPs == None or IPs == []:
            raise Exception
        return IPs

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
        while 1:
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
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(None, writer)

    async def switch(self, reader, writer):
        try:
            while 1:
                data = await reader.read(32768)
                if data == b'':
                    raise Exception
                writer.write(data)
                await writer.drain()
        except BaseException as error:
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
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def redirect(self, writer, host):
        try:
            URL = self.host_list[b'blacklist'][self.is_banned(host)]
            if URL != None:
                if URL[0:4] != b'http' and URL in self.host_list[b'blacklist']['tag']:
                    URL = self.host_list[b'blacklist']['tag'][URL]
                if URL[0:4] == b'http':
                    writer.write(b'''HTTP/1.1 301 Moved Permanently\r\nLocation: ''' + URL + b'''\r\nConnection: close\r\n\r\n''')
                else:
                    writer.write(b'''HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n''')
                await writer.drain()
                await self.clean_up(writer)
        except Exception as error:
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
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)
    
    async def updater_cache(self):
        try:
            self.exception_list_cache = dict()
            while 1:
                for uuid in self.config['uuid']:
                    path = self.local_path + '/Cache/' + uuid.decode('utf-8') + '.json'
                    if os.path.exists(path):
                        with open(path, 'rb') as file:
                            content = file.read()
                            self.exception_list_cache[uuid + b'_compressed'] = gzip.compress(content, 2)
                await asyncio.sleep(60)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

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
    def is_ip(host):
        try:
            if b':' in host or int(host[host.rfind(b'.') + 1:]):
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

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
        if host in self.host_list[b'blacklist']:
            return host
        sigment_length = len(host)
        while 1:
            sigment_length = host.rfind(b'.', 0, sigment_length) - 1
            if sigment_length <= -1:
                break
            if host[sigment_length + 1:] in self.host_list[b'blacklist']:
                return host[sigment_length + 1:]
        return None

    def add_host(self, host, uuid):
        if uuid not in self.host_list:
            self.host_list[uuid] = set()
        self.host_list[uuid].add(host)

    async def write_host(self):
        while 1:
            for x in self.host_list:
                if x != b'blacklist' and len(self.host_list[x]) > 0:
                    server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host='127.0.0.1', port=self.config['port']+1),5)
                    server_writer.write(str(list(self.host_list[x])).encode('utf-8')+b'\r\n'+x+b'\r\nhost\r\n\r\n')
                    await server_writer.drain()
                    await self.clean_up(None, server_writer)
                    self.host_list[x].clear()
            await asyncio.sleep(60)

    async def write_log(self):
        while 1:
            if len(self.log) > 0:
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host='127.0.0.1',port=self.config['port'] + 1),5)
                server_writer.write(str(self.log).encode('utf-8') + b'\r\n\r\nlog\r\n\r\n')
                await server_writer.drain()
                await self.clean_up(None, server_writer)
                self.log.clear()
            await asyncio.sleep(60)

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

    def get_proxy_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context

    @staticmethod
    def get_normal_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context
    
    async def ipv4_test(self):
        tasks = [('8.8.8.8',53), ('1.1.1.1',53),('ipv4.test-ipv6-vm3.comcast.net',443), ('ipv4.lookup.test-ipv6.com',443),
                 ('ipv4.test-ipv6.epic.network',443)]
        fail = 0
        for task in tasks:
            server_writer = None
            try:
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=task[0], port=task[1]), 1)
                await self.clean_up(server_writer)
                break
            except Exception as error:
                fail += 1
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer)
        if fail >= len(tasks):
            self.ipv6 = False

    async def ipv6_test(self):
        tasks = [('2001:4860:4860::8888',53), ('2606:4700:4700::1111',53),('ipv6.test-ipv6-vm3.comcast.net',443), ('ipv6.lookup.test-ipv6.com',443),
                 ('ipv6.test-ipv6.epic.network',443)]
        fail = 0
        for task in tasks:
            server_writer = None
            try:
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=task[0], port=task[1]), 1)
                await self.clean_up(server_writer)
                break
            except Exception as error:
                fail += 1
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer)
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
        for x in [0.5,1,1,2,4]:
            ipv4, ipv6 = await asyncio.gather(self.query_worker(host, 'A', doh), self.query_worker(host, 'AAAA', doh))
            if ipv4 or ipv6:
                break
            await asyncio.sleep(x)
        if not ipv4:
            ipv4 = []
        if not ipv6:
            ipv6 = []
        result = {'A':ipv4,'AAAA':ipv6,'ALL':ipv4+ipv6}
        if ipv4 or ipv6:
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
        return result

    async def query_worker(self, host, q_type, doh):
        try:
            if q_type == 'A':
                mq_type = 1
            elif q_type == 'AAAA':
                mq_type = 28
            else:
                raise Exception
            done, pending, = await asyncio.wait(await self.make_tasks(host, mq_type, doh),return_when=asyncio.FIRST_COMPLETED)
            for x in pending:
                x.cancel()
            results = []
            for x in range(len(done)):
                result = done.pop().result()
                if result:
                    results.append(result)
            if not results:
                return None
            for x in results:
                result = self.dns_decoder(x[0],mq_type,x[1])
                if result['error'] == None and result['answers']:
                    IPs = []
                    for y in result['answers']:
                        IPs.append(y['rdata'])
                    return IPs
            return None
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def make_tasks(self, host, mq_type, doh):
        try:
            query, ID = self.dns_encoder(host,mq_type)
            tasks = []
            for x in self.config['normal_dns']:
                tasks.append(asyncio.create_task(self.get_normal_query_response(query, ID, (x, 53))))
            if doh:
                for x in self.config['doh_dns']:
                    v4 = await self.resolve('A', x, False)
                    v6 = await self.resolve('AAAA', x, False)
                    if v4 != []:
                        tasks.append(asyncio.create_task(self.get_doh_query_response(query, ID, (v4[0], 443), x)))
                    if v6 != []:
                        tasks.append(asyncio.create_task(self.get_doh_query_response(query, ID, (v6[0], 443), x)))
            return tasks
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    async def get_normal_query_response(self, query, ID, address):
        s = None
        try:
            if self.is_ipv6(address[0]):
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            await self.loop.sock_connect(s, (address[0].decode('utf-8'),address[1]))
            await self.loop.sock_sendall(s, query)
            result = await asyncio.wait_for(self.loop.sock_recv(s, 512),4)
            return result, ID
        except Exception as error:
            await asyncio.sleep(5)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(s)
        finally:
            await self.clean_up(s)

    async def get_doh_query_response(self, query, ID, address, hostname):
        server_writer = None
        try:
            server_reader, server_writer = await asyncio.open_connection(host=address[0],
                                                                         port=address[1],
                                                                         ssl=self.normal_context,
                                                                         server_hostname=hostname,
                                                                         ssl_handshake_timeout=5)
            server_writer.write(b'GET /dns-query?dns=' + base64.b64encode(query).rstrip(b'=') + b' HTTP/1.1\r\nHost: ' + hostname + b'\r\nContent-type: application/dns-message\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62\r\n\r\n')
            await server_writer.drain()
            result = await asyncio.wait_for(server_reader.read(4096),4)
            result = result[result.find(b'\r\n\r\n')+4:]
            return result, ID
        except Exception as error:
            await asyncio.sleep(5)
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(server_writer)
        finally:
            await self.clean_up(server_writer)

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


class yashmak_log():
    def __init__(self,start_time,local_path, port):
        self.loop = asyncio.new_event_loop()
        listener = socket.create_server(address=('127.0.0.1', port), family=socket.AF_INET, dualstack_ipv6=False)
        server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048)
        self.host_list = dict()
        self.log = []
        self.local_path = local_path
        self.start_time = start_time
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(server)
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.write_log())
        self.loop.run_forever()
    
    async def handler(self, client_reader, client_writer):
        try:
            data = b''
            while 1:
                data += await client_reader.read(65536)
                if data[-4:] == b'\r\n\r\n':
                    data, key, instruction = data[:-4].decode('utf-8').split('\r\n')
                    break
            if instruction == 'host':
                data = data[1:-1]
                data = data.replace("b'", '')
                data = data.replace("'", '')
                data = data.split(', ')
                if key not in self.host_list:
                    self.host_list[key] = set()
                for x in data:
                    self.host_list[key].add(x)
            elif instruction == 'log':
                data = data[1:-1]
                data = data.replace('"', '')
                data = data.replace('),', ')),')
                data = data.split('), ')
                for x in data:
                    self.log.append(x)
            await self.clean_up(client_writer, None)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, None)
    
    async def write_host(self):
        while 1:
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
        while 1:
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
        self.host_list = dict()
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.geoip_list = []
        self.load_config()
        self.load_lists()
        self.get_time()
        self.edit_iptables()

    def run_forever(self):
        # start log server
        p = multiprocessing.Process(target=yashmak_log,args=(self.start_time,self.local_path,self.config['port']+1))
        p.start()
        # start normal workers
        for x in range(os.cpu_count()):
            p = multiprocessing.Process(target=yashmak_worker,args=(self.config,self.host_list,self.dns_pool,self.dns_ttl,self.geoip_list,self.exception_list_name,self.local_path,self.utc_difference,self.start_time))
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
                p = multiprocessing.Process(target=yashmak_worker, args=(config, self.host_list, self.dns_pool, self.dns_ttl, self.geoip_list, self.exception_list_name,self.local_path, self.utc_difference, self.start_time))
                p.start()
                ps.append(p)
            while config['port'] == self.get_calculated_port():
                time.sleep(1)
            for x in ps:
                x.kill()

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
        self.utc_difference = offset
        self.start_time = time.localtime()

    def edit_iptables(self):
        try:
            os.system("iptables -P INPUT ACCEPT")
            os.system("iptables -P OUTPUT ACCEPT")
            os.system("ip6tables -P INPUT ACCEPT")
            os.system("ip6tables -P OUTPUT ACCEPT")
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

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
            self.config['doh_dns'] = list(map(self.encode, self.config['doh_dns']))
        else:
            example = {'geoip': '','blacklist': '','hostlist': '','cert': '', 'key': '', 'uuid': [''], 'normal_dns': [''],
                       'doh_dns': [''], 'ip': '', 'port': ''}
            with open(self.local_path + '/config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_lists(self):
        with open(self.config['geoip'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]),int(network[-1])])
        self.geoip_list.sort()
        self.exception_list_name = self.config['uuid']
        if not os.path.exists(self.local_path + '/Cache/'):
            os.makedirs(self.local_path + '/Cache/')
        for x in self.exception_list_name:
            self.host_list[x] = set()
        with open(self.config['blacklist'], 'r') as file:
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
        self.host_list[b'blacklist'] = data
        with open(self.config['hostlist'], 'r') as file:
            data = json.load(file)
        for x in data:
            self.dns_pool[x.encode('utf-8')] = data[x]
            self.dns_ttl[x.encode('utf-8')] = time.time() * 2

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