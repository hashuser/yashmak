Language: [English](https://github.com/hashuser/yashmak/blob/master/README_en.md) [简体中文](https://github.com/hashuser/yashmak/blob/master/README.md)
## Yashmak基于Python3.10轻量级代理
* 流量智能分流（基于用户行为提高准确度）
* 基于多进程uvloop框架，支持多核，承载海量并发
* TCP预连接池，显著降低延迟（0-RTT）
* 无DNS泄漏
* 非阻塞异步DNS查询
* 自动签发TLS自签证书
* 支持HTTP/Socks5代理协议
* Host屏蔽/重定向
* IPv4/IPv6 双协议栈
## 服务端
>### 安装(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/install.sh | bash
``` 
>### 配置
```
sudo Yashmak_config
```
```shell
# Example
{
    "geoip_list_path": "/root/Yashmak/geoip.json",  # IP addresses of (eg. China)
    "black_list_path": "/root/Yashmak/blacklist.json",  # Blacklist of domain
    "host_list_path": "/root/Yashmak/hostlist.json",  # Maps hostnames to IP addresses
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
    "ip": "::",  # Listening IP address
    "port": "443"  # Listening Port
}
```
>### 卸载
```
sudo Yashmak_uninstall
```
>### 重启
```
sudo systemctl restart Yashmak
```

## 如无法获取最新版本GCC/G++，将先编译GCC/G++，更新会耗费较长时间

>### OpenSSL更新(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_openssl.sh | bash
``` 
>### Python更新(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_python.sh | bash
```
>### GCC更新(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_gcc.sh | bash
```
>### All-In-One(Ubuntu 18.04TLS+)
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/all_in_one.sh | bash
```
## Yashmak服务端架构
![image](https://github.com/hashuser/yashmak/raw/master/recourse/server.png)
## Yashmak客户端架构
![image](https://github.com/hashuser/yashmak/raw/master/recourse/local.png)
## Yashmak项目思路
* **不使用非必要的额外加密手段**
  * 截止2022/01/22全球约91%[<sup>[Chrome浏览器统计数据]</sup>](https://transparencyreport.google.com/https)的站点使用了TLS/SSL，因此浏览器已对此部分流量进行了1次加密。考虑到可能存在的SNI阻断，以及20%的未使用加密的站点，Yashmak使用TLS1.3(X25519,AES_256_GCM)对所有流量实行了2次加密。不同于Shadowsocks或其他项目的是，Yashmak即不使用任何私有加密算法，也不会使用预共享密钥对流量使用对称加密算法进行加密。
* **不使用非必要的应用层协议**
  * Yashmak项目认为，在任何试图使用应用层协议包装流量的做法都是毫无意义的。由于已使用TLS1.3对所有流量进行2次加密，流量对于外部观察者而言是黑盒无法直接获取报文特征，任何基于报文内容的DPI全部失效，只能通过旁信道特征进行分析猜测(DNS请求，包长度，访问频率等)。鉴于传输的流量已具备正常的包长度特征，因此额外的应用层协议包装不能带来任何好处只会降低速度。
* **不使用MUX(多路复用)**
  * 建立TCP的开销确实巨大，但是少量连接的情况下这种开销可以忽略不计。作为代理所能做的是降低因代理而产生的额外性能开销，MUX使代理需要对数据帧进行额外的解码与合并，导致整体效率降低。同时由于HTTP/2的逐渐普及，截止2020/04/15全球约44%[<sup>[W3Tech统计数据]</sup>](https://w3techs.com/technologies/details/ce-http2)的站点使用了HTTP/2。由于HTTP/2中MUX默认开启也是HTTP/2不同于HTTP/1.1的显著特征之一，因此额外的MUX显得毫无意义。
* **客户端不使用传统PAC**
  * 传统PAC需要浏览器支持，相同的Javascript在不同的浏览器中性能差距大，同时无法简单的做到全局分流。Yashmak项目对此做出改进，内置高性能智能分流器(单个请求**平均耗时0.01ms**)，所有经过Yashmak的流量都会被合理科学的进行分流。Yashmak客户端中的ChinaList包含所有已知A/AAAA记录为中国IP的Host，每次请求都会通过智能分流器筛选，如所请求的Host在本地的ChinaList中则会直连，反之则将请求转发到代理服务器，过程中不进行任何DNS解析，避免可能的DNS泄露发生。代理服务器将通过GEOIP筛选所有请求，如DNS解析得到的A/AAAA记录为中国IP则将请求的Host保存到文件中，并正常代理该请求。Yashmak客户端每60s会从代理服务器获取ChinaList更新，更新完成后立即生效。基于用户请求每个UUID会获得独一无二的ChinaList。
* **使用OpenSSL**
  * 使用OpenSSL可以减少 **Client Hello** 泄露的特征，更容易隐藏在正常TLS流量中。
## HMAK协议
HMAK是Yashmak专有协议，轻量快速，用于对代理服务器发送指令
|36字节|2字节(有符号,Big Endian)|X字节|1字节|Y字节|1字节|1字节|1字节|
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
|UUID|指令长度L|地址A|'\n'分隔标识|端口P|'\n'分隔标识|类型T|'\n'分隔标识|

其中:
* UUID: 预共享的UUID用于认证请求合法性
* 指令长度:
  * L>0: L字节的指令
  * L=0: 心跳包
  * L=-2: TCP_Ping请求
  * L=-3: ChinaList更新请求(Gzip压缩)
* 连接复用:
  * T = 0: 禁用
  * T = 1: 启用
## 注意事项
* 请确保客户端与代理服务器间链路正常，平均丢包率≤10%，安装脚本默认开启BBRv1
![image](https://raw.githubusercontent.com/hashuser/yashmak/master/recourse/2020-04-19%20132834.png)
