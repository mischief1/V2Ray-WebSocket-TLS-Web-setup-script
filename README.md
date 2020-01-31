# V2Ray-WebSocket(ws)+TLS(1.3)+Web搭建/管理脚本
此脚本需要一个解析到服务器的域名!!!!

此脚本需要一个解析到服务器的域名!!!!

此脚本需要一个解析到服务器的域名!!!!

(支持cdn解析)

## 脚本特性

1.集成安装bbr(2)加速 
 
2.支持多种系统(Ubuntu CentOS Debian ...) 
 
3.集成TLS配置多版本安装选项 
 
4.集成删除防火墙、阿里云盾功能

5.使用nginx作为网站服务

6.使用acme.sh自动申请域名证书
 
## 脚本使用说明

### 1. 安装wget

Debian基系统(包括Ubuntu、Debian)：

```bash
apt update && apt install wget
```

Red Hat基系统(包括CentOS)：

```bash
yum install wget
```

### 2. 获取脚本

```bash
wget "https://github.com/kirin10000/V2Ray-WebSocket-TLS-Web-setup-script/raw/master/v2ray-WebSocket(ws)+TLS(1.3)+Web-setup.sh"
```

### 3. 增加脚本可执行权限

```bash
chmod +x "v2ray-WebSocket(ws)+TLS(1.3)+Web-setup.sh"
```

### 4. 执行脚本

```bash
./"v2ray-WebSocket(ws)+TLS(1.3)+Web-setup.sh"
```

### 5. 根据脚本提示完成安装

### 6. 其他说明

1.有些阿里云非大陆ecs443端口被阻断，这个脚本搭建的无法运行。

2.推荐使用cloudflare进行dns解析。

## 注

1.本文链接(官网)：https://github.com/kirin10000/V2Ray-WebSocket-TLS-Web-setup-script

2.参考教程：https://www.v2ray.com/

3.域名证书申请：https://github.com/acmesh-official/acme.sh

4.bbr脚本来自：https://github.com/teddysun/across/blob/master/bbr.sh

5.bbr2脚本来自：https://github.com/yeyingorg/bbr2.sh (ubuntu debian) https://github.com/jackjieYYY/bbr2 (centos)

6.此脚本仅供交流学习使用，请勿使用此脚本行违法之事。网络非法外之地，行非法之事，必将接受法律制裁！！
