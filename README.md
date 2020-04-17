## Yashmak基于Python3.8轻量级代理
* 流量智能分流（基于用户行为提高准确度）
* 基于asyncio框架, 支持海量并发
* TCP预连接池，显著降低延迟（0-RTT）
* 无DNS泄漏
* 自动签发TLS自签证书
* 支持HTTP/Socks5代理协议
* Host屏蔽/重定向

### 安装
```
sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/install.sh | bash
``` 
### 配置
```
sudo Yashmak_config
```
### 卸载
```
sudo Yashmak_uninstall
```
### 重启
```
sudo systemctl restart Yashmak
```
## Yashmak项目思路
* **不使用非必要的额外加密手段**
  * 截止2020/04/15全球约85%[<sup>[Chrome浏览器统计数据]</sup>](https://transparencyreport.google.com/https)的站点使用了TLS/SSL，因此浏览器已对此部分流量进行了1次加密。考虑到可能存在的SNI阻断，以及20%的未使用加密的站点，Yashmak使用TLS1.3(X25519,AES_256_GCM)对所有流量实行了2次加密。不同于Shadowsocks或其他项目的是，Yashmak即不使用任何私有加密算法，也不会使用预共享密钥对流量使用对称加密算法进行加密。
* **不使用非必要的应用层协议**
  * Yashmak项目认为，在任何试图使用应用层协议包装流量的做法都是毫无意义的。由于已使用TLS1.3对所有流量进行2次加密，流量对于外部观察者而言是黑盒无法直接获取报文特征，任何基于报文内容的DPI全部失效，只能通过旁信道特征进行分析猜测(DNS请求，包长度，访问频率等)。鉴于传输的流量已具备正常的包长度特征，因此额外的应用层协议包装不能带来任何好处只会降低速度。
* **不使用MUX(多路复用)**
  * 建立TCP的开销确实巨大，但是少量连接的情况下这种开销可以忽略不计。作为代理所能做的是降低因代理而产生的额外性能开销，MUX使代理需要对数据帧进行额外的解码与合并，导致整体效率降低。同时由于HTTP/2的逐渐普及，截止2020/04/15全球约44%[<sup>[W3Tech统计数据]</sup>](https://w3techs.com/technologies/details/ce-http2)的站点使用了HTTP/2。由于HTTP/2中MUX默认开启也是HTTP/2不同于HTTP/1.1的显著特征之一，因此额外的MUX显得毫无意义。
* **客户端不使用传统PAC**
  * 传统PAC需要浏览器支持，相同的Javascript在不同的浏览器中性能差距大，同时无法简单的做到全局分流。Yashmak项目对此做出改进，内置高性能智能分流器(单个请求**平均耗时0.01ms**)，所有经过Yashmak的流量都会被合理科学的进行分流。Yashmak客户端中的ChinaList包含所有已知A/AAAA记录为中国IP的Host，每次请求都会通过智能分流器筛选，如所请求的Host在本地的ChinaList中则会直连，反之则将请求转发到代理服务器，过程中不进行任何DNS解析，避免可能的DNS泄露发生。代理服务器将通过GEOIP筛选所有请求，如DNS解析得到的A/AAAA记录为中国IP则将请求的Host保存到文件中，并正常代理该请求。Yashmak客户端每60s会从代理服务器获取ChinaList更新，更新完成后立即生效。基于用户请求每个UUID会获得独一无二的ChinaList。
## HMAK协议
HMAK是Yashmak专有协议，轻量快速，用于对代理服务器发送指令
|36字节|2字节(有符号,Big Endian)|X字节|1字节|Y字节|1字节|
|:---:|:---:|:---:|:---:|:---:|:---:|
|UUID|指令长度L|地址A|'/n'分隔标识|端口P|'/n'分隔标识|

其中:
* UUID: 预共享的UUID用于认证请求合法性
* 指令长度:
  * L>0: L字节的指令
  * L=0: 心跳包
  * L=-1: ChinaList更新请求(不压缩)
  * L=-2: TCP_Ping请求
  * L=-3: ChinaList更新请求(Gzip压缩)
