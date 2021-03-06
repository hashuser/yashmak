import asyncio
import multiprocessing
from dns import message
import socket
import ssl
import json
import os
import sys
import ipaddress
import traceback
import gzip
import time
import ntplib
import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
class yashmak_worker():
    def __init__(self,config,host_list,geoip_list,exception_list_name,local_path,utc_difference,start_time):
        self.config = config
        self.loop = asyncio.get_event_loop()
        if socket.has_dualstack_ipv6():
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET6,
                                            reuse_port=True,dualstack_ipv6=True)
        else:
            listener = socket.create_server(address=(self.config['ip'], self.config['port']), family=socket.AF_INET,
                                            reuse_port=True,dualstack_ipv6=False)
        server = asyncio.start_server(client_connected_cb=self.handler, sock=listener, backlog=2048,ssl=self.get_context())
        self.host_list = host_list
        self.geoip_list = geoip_list
        self.exception_list_name = exception_list_name
        self.local_path = local_path 
        self.utc_difference = utc_difference
        self.start_time = start_time
        self.dns_pool = dict()
        self.dns_ttl = dict()
        self.log = []
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_task(server)
        self.loop.create_task(self.write_host())
        self.loop.create_task(self.write_log())
        self.loop.create_task(self.updater_cache())
        self.loop.create_task(self.clear_cache())
        self.loop.run_forever()

    async def handler(self, client_reader, client_writer):
        try:
            server_writer = None
            tasks = None
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
                    await self.redirect(client_writer, host, uuid)
                    address = await self.resolve('A',host)
                    self.is_china_ip(address, host, uuid)
                    server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(host=address, port=port),5)
                    await asyncio.gather(self.switch(client_reader, server_writer, client_writer),
                                         self.switch(server_reader, client_writer, server_writer))
                elif data == -1:
                    await self.updater(client_writer, uuid, False)
                elif data == -2:
                    await self.TCP_ping(client_writer, client_reader)
                elif data == -3:
                    await self.updater(client_writer, uuid, True)
                elif data == -4:
                    await self.echo(client_writer, client_reader)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer, server_writer)

    def HTTP_header_decoder(self, header):
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

    async def switch(self, reader, writer, other):
        try:
            while 1:
                data = await reader.read(32768)
                if data == b'':
                    raise Exception
                writer.write(data)
                await writer.drain()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer, other)

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

    async def echo(self, writer, reader):
        try:
            writer.write(b'ok')
            await writer.drain()
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(writer)

    async def redirect(self, writer, host, uuid):
        try:
            URL = self.host_list[b'blacklist'][self.is_banned(host, uuid)]
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

    async def updater(self, writer, uuid, compress=False):
        try:
            if len(uuid) != 36 or b'.' in uuid or b'/' in uuid or b'\\' in uuid:
                raise Exception
            if (uuid + b'_compressed') in self.exception_list_cache and (uuid + b'_normal') in self.exception_list_cache:
                if compress:
                    writer.write(self.exception_list_cache[uuid + b'_compressed'])
                else:
                    writer.write(self.exception_list_cache[uuid + b'_normal'])
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
                            self.exception_list_cache[uuid + b'_normal'] = content
                            self.exception_list_cache[uuid + b'_compressed'] = gzip.compress(content, 2)
                await asyncio.sleep(60)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            
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

    def is_ip(self,host):
        try:
            if b':' in host or int(host[host.rfind(b'.') + 1:]):
                return True
        except ValueError as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        return False

    def is_china_ip(self, ip, host, uuid):
        if self.is_ip(host):
            return False
        for x in [b'google',b'youtube',b'wikipedia',b'twitter']:
            if x in host:
                return False
        ip = ip.decode('utf-8')
        ip = ip.replace('::ffff:','',1)
        ip = int(ipaddress.ip_address(ip))
        left = 0
        right = len(self.geoip_list) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if self.geoip_list[mid][0] <= ip and ip <= self.geoip_list[mid][1]:
                self.add_host(self.conclude(host), uuid)
                return True
            elif self.geoip_list[mid][1] < ip:
                left = mid + 1
            elif self.geoip_list[mid][0] > ip:
                right = mid - 1
        return False

    def is_banned(self, host, uuid):
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
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context

    async def resolve(self,q_type,host):
        if self.is_ip(host):
            return host
        elif host in self.dns_pool and (time.time() - self.dns_ttl[host]) < 600:
            return self.dns_pool[host]
        else:
            return await self.query(host, q_type)
        await self.clean_up(client_writer, None)

    async def query(self,host,q_type):
        try:
            if q_type == 'A':
                mq_type = 1
            elif q_type == 'AAAA':
                mq_type = 28
            elif q_type == 'CNAME':
                mq_type = 5
            query = message.make_query(host.decode('utf-8'), mq_type)
            query = query.to_wire()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            await self.loop.sock_connect(s, ('8.8.8.8', 53))
            await self.loop.sock_sendall(s, query)
            result = await asyncio.wait_for(self.loop.sock_recv(s, 1024), 4)
            await self.clean_up(s, None)
            result = message.from_wire(result)
            result = self.decode(str(result), q_type)
            self.dns_pool[host] = result
            self.dns_ttl[host] = time.time()
            return result
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(s, None)

    def decode(self,result,type):
        type = ' ' + type.upper() + ' '
        position = result.find(type)
        if position < 0:
            return None
        result = result[position + len(type):result.find('\n', position)]
        if result[-1] == '.':
            result = result[:-1]
        return result.encode('utf-8')

    async def clear_cache(self):
        while 1:
            try:
                for x in list(self.dns_pool.keys()):
                    if (time.time() - self.dns_ttl[x]) > 600:
                        del self.dns_pool[x]
                        del self.dns_ttl[x]
                await asyncio.sleep(300)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None


class yashmak_log():
    def __init__(self,start_time,local_path, port):
        self.loop = asyncio.get_event_loop()
        listener = socket.create_server(address=('127.0.0.1', port), family=socket.AF_INET,
                                            dualstack_ipv6=False)
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

    def exception_handler(self, loop, context):
        pass


class yashmak():
    def __init__(self):
        self.host_list = dict()
        self.geoip_list = []
        self.load_config()
        self.load_lists()
        self.get_time()

    def run_forever(self):
        #start log server
        p = multiprocessing.Process(target=yashmak_log,args=(self.start_time,self.local_path,self.config['port']+1))
        p.start()
        #start workers
        for x in range(os.cpu_count()):
            p = multiprocessing.Process(target=yashmak_worker,args=(self.config,self.host_list,self.geoip_list,self.exception_list_name,self.local_path,self.utc_difference,self.start_time))
            p.start()

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

    def load_config(self):
        self.local_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        if os.path.exists(self.local_path + '/config.json'):
            with open(self.local_path + '/config.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
            self.config['uuid'] = self.UUID_detect(set(list(map(self.encode, self.config['uuid']))))
            self.config['port'] = int(self.config['port'])
        else:
            example = {'geoip': '','blacklist': '','cert': '', 'key': '', 'uuid': [''], 'ip': '', 'port': ''}
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

    def UUID_detect(self, UUIDs):
        for x in UUIDs:
            if len(x) != 36:
                raise Exception
        return UUIDs

    def translate(self, content):
        return content.replace('\\', '/')

    def encode(self, data):
        return data.encode('utf-8')


if __name__ == '__main__':
    server = yashmak()
    server.run_forever()