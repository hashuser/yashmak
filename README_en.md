## Yashmak - a lightweight proxy based on Python3.10 
* Intelligent flow distribution (based on user behavior to improve accuracy)
* Based on the multi-process uvloop framework, it supports multi-core and carries massive concurrency
* TCP pre-connection pool, significantly reducing latency (0-RTT)
* No DNS leaks
* Non-blocking asynchronous DNS query
* Automatically issue TLS self-signed certificates
* Support HTTP/Socks5 proxy protocol
* Host blocking/redirection
* IPv4/IPv6 Dual Stack

### Install (Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/install.sh | bash
```
### configuration
```
sudo Yashmak_config
```
```shell
# Example
{
    "geoip": "/root/Yashmak/geoip.json",  # IP addresses of China
    "blacklist": "/root/Yashmak/blacklist.json",  # Blacklist of domain
    "hostlist": "/root/Yashmak/hostlist.json",
    "cert": "/root/Yashmak/Certs/server.crt",  # ECC Public Key
    "key": "/root/Yashmak/Certs/server.key",  # ECC Private Key
    "uuid": [
        "d240eb37-fc4d-4bce-9404-2b338eccdf07"  # UUID
    ],
    "normal_dns": [
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111"
    ],
    "doh_dns": [
        "1.1.1.1",
        "dns.google"
    ],
    "ip": "::",
    "port": "443"
}
```
### Uninstall
```
sudo Yashmak_uninstall
```
### reboot
```
sudo systemctl restart Yashmak
```

## If the latest version of GCC/G++ cannot be obtained, GCC/G++ will be compiled first, and the update will take a long time

### OpenSSL update (Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_openssl.sh | bash
```
### Python update (Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_python.sh | bash
```
### GCC update (Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_gcc.sh | bash
```
### All-In-One(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/all_in_one.sh | bash
```
## Yashmak server architecture
![image](https://github.com/hashuser/yashmak/raw/master/recourse/server.png)
## Yashmak client architecture
![image](https://github.com/hashuser/yashmak/raw/master/recourse/local.png)
## Yashmak Project Ideas
* **Do not use unnecessary additional encryption methods**
   * As of 2022/01/22, about 91% of [<sup>[Chrome browser statistics]</sup>](https://transparencyreport.google.com/https) sites in the world use TLS/SSL, so browsing The server has already encrypted this part of the traffic once. Considering possible SNI blocking and 20% of sites that do not use encryption, Yashmak uses TLS1.3 (X25519, AES_256_GCM) to encrypt all traffic twice. Unlike Shadowsocks or other projects, Yashmak neither uses any proprietary encryption algorithms nor uses pre-shared keys to encrypt traffic with symmetric encryption algorithms.
* **Do not use non-essential application layer protocols**
   * The Yashmak project believes that any attempt to wrap traffic using an application layer protocol is pointless. Since TLS1.3 has been used to encrypt all traffic twice, the traffic is a black box for external observers and cannot directly obtain packet characteristics. Any DPI based on packet content is invalid, and can only be analyzed and guessed through side channel characteristics. (DNS request, packet length, access frequency, etc.). Given that the transmitted traffic already has normal packet length characteristics, the additional application-layer protocol wrapping does not bring any benefit but only slows down the speed.
* **Does not use MUX (multiplexing)**
   * The overhead of establishing TCP is indeed huge, but this overhead is negligible in the case of a small number of connections. What a proxy can do is to reduce the additional performance overhead caused by the proxy. MUX makes the proxy need to perform additional decoding and merging of data frames, resulting in a decrease in overall efficiency. At the same time, due to the gradual popularity of HTTP/2, as of 2020/04/15, about 44% of the world [<sup>[W3Tech statistics]</sup>](https://w3techs.com/technologies/details/ce-http2) of sites use HTTP/2. Since MUX is turned on by default in HTTP/2 is also one of the distinctive features of HTTP/2 different from HTTP/1.1, so the additional MUX is meaningless.
* **Client does not use legacy PAC**
   * Traditional PAC requires browser support. The performance of the same Javascript varies greatly in different browsers, and it is impossible to simply implement global distribution. The Yashmak project has improved on this, with a built-in high-performance intelligent shunt (a single request** takes an average of 0.01ms**), and all traffic passing through Yashmak will be shunted reasonably and scientifically. The ChinaList in the Yashmak client contains all hosts with known A/AAAA records as Chinese IPs. Each request will be filtered by an intelligent shunt. If the requested Host is in the local ChinaList, it will be directly connected, otherwise the request will be forwarded To the proxy server, no DNS resolution is performed during the process to avoid possible DNS leaks. The proxy server will filter all requests through GEOIP. If the A/AAAA record obtained by DNS resolution is a Chinese IP, it will save the requested Host to a file and proxy the request normally. The Yashmak client will obtain the ChinaList update from the proxy server every 60s, and it will take effect immediately after the update is completed. A unique ChinaList will be obtained for each UUID based on the user's request.
* **Using OpenSSL**
   * Using OpenSSL can reduce the characteristics of **Client Hello** leaks, which are easier to hide in normal TLS traffic.
## HMAK protocol
HMAK is Yashmak's proprietary protocol, lightweight and fast, used to send instructions to proxy servers
|36 bytes|2 bytes (signed, Big Endian)|X bytes|1 bytes|Y bytes|1 bytes|1 bytes|1 bytes|
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
|UUID|command length L|address A|'\n' delimiter|port P|'\n' delimiter|type T|'\n' delimiter|

in:
* UUID: The pre-shared UUID is used to authenticate the legitimacy of the request
* Instruction length:
   * L>0: L byte instruction
   * L=0: heartbeat packet
   * L=-2: TCP_Ping request
   * L=-3: ChinaList update request (Gzip compression)
* Connection multiplexing:
   * T = 0: disabled
   * T = 1: enable
## Precautions
* Please ensure that the link between the client and the proxy server is normal, the average packet loss rate is ≤10%, and the installation script enables BBRv1 by default
![image](https://raw.githubusercontent.com/hashuser/yashmak/master/recourse/2020-04-19%20132834.png)
