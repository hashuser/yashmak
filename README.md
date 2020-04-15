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
