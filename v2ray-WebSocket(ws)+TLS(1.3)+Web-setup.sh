#!/bin/bash


#定义几个颜色
tyblue()                           #天依蓝
{
    echo -e "\033[36;1m $1 \033[0m"
}
green()                            #水鸭青
{
    echo -e "\033[32;1m $1 \033[0m"
}
yellow()                           #鸭屎黄
{
    echo -e "\033[33;1m $1 \033[0m"
}
red()                              #姨妈红
{
    echo -e "\033[31;1m $1 \033[0m"
}


#读取域名
readDomain()
{
    clear
    tyblue "**********************关于域名的说明**********************"
    tyblue "假设你的域名是abcd.com，则:"
    tyblue "一级域名为:abcd.com(主机记录为 @ )"
    tyblue "二级域名为:xxx.abcd.com(如www.abcd.com，pan.abcd.com，前缀为主机记录)"
    tyblue "三级域名为:xxx.xxx.abcd.com"
    tyblue "可以在cmd里用ping+域名来查看域名的解析情况"
    tyblue "**********************************************************"
    echo
    tyblue "**********************************************************"
    tyblue "若你有多个域名，但想只用某个解析到此服务器的域名，请选择2并输入该域名"
    tyblue "注:在这里拥有相同一级域名的二(三)级域名也算不同域名"
    tyblue "如:www.abcd.com，pan.abcd.com，abcd.com，abcd2.com算不同域名"
    echo
    tyblue "********************请选择域名解析情况********************"
    tyblue "1.一级域名和  www.一级域名  都解析到此服务器上(支持cdn解析)"
    tyblue "2.仅一级域名或某个二(三)级域名解析到此服务器上(支持cdn解析)"
    domainconfig=777
    while [ "$domainconfig" != "1" -a "$domainconfig" != "2" ]
    do
        read -p "您的选择是：" domainconfig
    done
    case "$domainconfig" in
        1)
            tyblue "********************请输入一级域名(不带www.，http，:，/)********************"
            read -p "请输入域名：" domain
            ;;
        2)
            tyblue "****************请输入解析到此服务器的域名(不带http，:，/)****************"
            read -p "请输入域名：" domain
            ;;
    esac
}


#选择tls配置
readTlsConfig()
{
    clear
    tyblue "****************************************************************"
    tyblue "                     速度                        抗封锁性"
    tyblue "TLS1.2+1.3：  ++++++++++++++++++++          ++++++++++++++++++++"
    tyblue "仅TLS1.3：    ++++++++++++++++++++          ++++++++++++++++++"
    tyblue "****************************************************************"
    tyblue "经测试，当TLS1.2和TLS1.3并存的时候，v2ray会优先选择TLS1.3进行连接"
    green  "推荐使用TLS1.2+1.3"
    echo
    tyblue "1.TLS1.2+1.3"
    tyblue "2.仅TLS1.3"
    tlsVersion=777
    while [ "$tlsVersion" != "1" -a "$tlsVersion" != "2" ]
    do
        read -p "您的选择是："  tlsVersion
    done
}


#配置nginx(部分)
configtls_part()
{
cat > /etc/nginx/conf/nginx.conf <<EOF

user  root root;
worker_processes  4;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;
    include       /etc/nginx/conf.d/v2ray.conf;

    #log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
    #                  '\$status \$body_bytes_sent "\$http_referer" '
    #                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    #server {
        #listen       80;
        #server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        #location / {
        #    root   html;
        #    index  index.html index.htm;
        #}

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        #error_page   500 502 503 504  /50x.html;
        #location = /50x.html {
        #    root   html;
        #}

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \\.php\$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \\.php\$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts\$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\\.ht {
        #    deny  all;
        #}
    #}


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}
EOF
}


#配置nginx
configtls()
{
    configtls_part
cat > /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    return 301 https://$domain\$request_uri;
}
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
EOF
    if [ $tlsVersion -eq 2 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3;
    return 301 https://$domain\$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3;
    root /etc/nginx/html/$domain;
    index index.html;
    location /$path {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
    else
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    return 301 https://$domain\$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    root /etc/nginx/html/$domain;
    index index.html;
    location /$path {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
    fi
    if [ $domainconfig -eq 1 ]; then
        sed -i "s/server_name $domain/& www.$domain/" /etc/nginx/conf.d/v2ray.conf
    fi
}


#配置新域名tls
new_tls()
{
    configtls_part
    old_domain=$(grep -m 1 "server_name" /etc/nginx/conf.d/v2ray.conf)
    old_domain=${old_domain%';'*}
    case "$tlsVersion" in
        2)
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3;
    root /etc/nginx/html/$domain;
    index index.html;
    location /$path {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
            ;;
        1)
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    root /etc/nginx/html/$domain;
    index index.html;
    location /$path {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
            ;;
    esac
    if [ $domainconfig -eq 1 ]; then
        sed -i "0,/$old_domain/s//$old_domain $domain www.$domain/" /etc/nginx/conf.d/v2ray.conf
        sed -i "s/server_name $domain/& www.$domain/" /etc/nginx/conf.d/v2ray.conf
    else
        sed -i "0,/$old_domain/s//$old_domain $domain/" /etc/nginx/conf.d/v2ray.conf
    fi
}


#升级系统
updateSystem()
{
    systemVersion=`lsb_release -r --short`
    clear
    tyblue "********************请选择升级系统版本********************"
    tyblue "1.最新beta版(现在是20.04)(2020/01/21)"
    tyblue "2.最新稳定版(现在是19.10)(2020/01/21)"
    tyblue "3.最新LTS版(现在是18.04)(2020/01/21)"
    tyblue "*************************版本说明*************************"
    tyblue "beta版：就是测试版啦"
    tyblue "稳定版：就是稳定版啦"
    tyblue "LTS版：长期支持版本，可以理解为超级稳定版"
    tyblue "*************************注意事项*************************"
    tyblue "1.升级系统仅对ubuntu有效，非ubuntu系统将仅更新软件包"
    yellow "2.升级系统可能需要15分钟或更久"
    yellow "3.升级系统完成后将会重启，重启后，请再次运行此脚本完成剩余安装"
    yellow "4.有的时候不能一次性更新到所选择的版本，可能要更新两次，所以更新完"
    yellow "  第一次重启后，若还未升级到选定版本，请再选择相同的升级版本"
    yellow "5.升级过程中若有问话/对话框，如果看不懂，优先选择yes/y/第一个选项"
    yellow "6.若升级过程中与ssh断开连接，建议重置系统"
    yellow "7.升级系统后ssh超时时间将会恢复默认"
    tyblue "8.ubuntu20.04暂不支持bbr2(支持bbr)"
    tyblue "**********************************************************"
    green  "您现在的系统版本是$systemVersion"
    tyblue "**********************************************************"
    echo
    updateconfig=5
    while [ "$updateconfig" != "1" -a "$updateconfig" != "2" -a "$updateconfig" != "3" ]
    do
        read -p "您的选择是：" updateconfig
    done
    yum update
    apt dist-upgrade -y
    echo '[DEFAULT]' > /etc/update-manager/release-upgrades
    echo 'Prompt=lts' >> /etc/update-manager/release-upgrades
    case "$updateconfig" in
        1)
            do-release-upgrade
            do-release-upgrade -d
            ;;
        2)
            sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
            do-release-upgrade
            ;;
        3)
            do-release-upgrade
            ;;
    esac
    apt autoremove -y
    apt clean
    yum clean all
}


#升级系统组件
doupdate()
{
    clear
    tyblue "*******************是否将更新系统组件？*******************"
    green  "1.更新已安装软件，并升级系统(仅对ubuntu有效)"
    green  "2.仅更新已安装软件"
    red    "3.不更新"
    tyblue "*************************注意事项*************************"
    tyblue "升级系统仅对ubuntu有效，非ubuntu系统选1等效于选2"
    tyblue "**********************************************************"
    echo
    ifupdate=5
    while [ "$ifupdate" != "1" -a "$ifupdate" != "2" -a "$ifupdate" != "3" ]
    do
        read -p "您的选择是：" ifupdate
    done
    case "$ifupdate" in
        1)
            updateSystem
            ;;
        2)
            tyblue "***************即将开始更新已安装软件***************"
            yellow "更新过程中若有问话/对话框，如果看不懂，优先选择yes/y/第一个选项"
            yellow "按回车键继续。。。"
            read rubbish
            yum update -y
            apt dist-upgrade -y
            apt autoremove -y
            apt clean
            yum autoremove -y
            yum clean all
            ;;
    esac
}


#删除防火墙
uninstall_firewall()
{
    ufw disable
    apt remove iptables -y
    chkconfig iptables off
    systemctl disable firewalld
    yum remove firewalld -y
    rm -rf /usr/local/aegis
    rm -rf /usr/local/cloudmonitor
    rm -rf /usr/sbin/aliyun-service
    #pkill wrapper.syslog.id
    #pkill wrapper
    pkill CmsGoAgent
    pkill aliyun-service
    service aegis stop
    #rm -rf /usr/bin/networkd-dispatcher
    #pkill networkd
    rm -rf /etc/init.d/aegis
}


#卸载v2ray和nginx
remove_v2ray_nginx()
{
    /etc/nginx/sbin/nginx -s stop
    service v2ray stop
    service v2ray disable
    rm -rf /usr/bin/v2ray 
    rm -rf /etc/v2ray
    rm -rf /etc/nginx
}


#安装bbr
install_bbr()
{
    clear
    tyblue "******************请选择要安装的bbr版本******************"
    tyblue "1.bbr"
    yellow "2.bbr2(beta)(Ubuntu、Debian)"
    yellow "3.bbr2(beta)(Centos)"
    red    "4.不安装"
    tyblue "*********************************************************"
    echo
    tyblue "********************关于bbr加速的说明********************"
    yellow "bbr加速可以大幅提升网络速度，建议安装"
    yellow "bbr2目前还在测试阶段，可能造成各种系统不稳定，甚至崩溃"
    yellow "bbr加速安装完成后系统可能会重启"
    yellow "若重启，请再次运行此脚本完成剩余安装"
    tyblue "装过一遍就不需要再装啦"
    tyblue "*********************************************************"
    echo
    bbrconfig=7
    while [ "$bbrconfig" != "1" -a "$bbrconfig" != "2" -a "$bbrconfig" != "3" -a "$bbrconfig" != "4" ]
    do
        read -p "您的选择是：" bbrconfig
    done
    case "$bbrconfig" in
        1)
            tyblue "****即将安装bbr加速，安装完成后可能会重启，若重启，请再次运行此脚本完成剩余安装****"
            yellow "按回车键以继续。。。。"
            read rubbish
            rm -rf bbr.sh
            if ! wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh ; then
                red    "获取bbr脚本失败"
                red    "你的服务器貌似没联网，或不支持ipv4"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x bbr.sh
            ./bbr.sh
            ;;
        2)
            tyblue "*********************即将安装bbr2加速，安装完成后服务器将会重启*********************"
            tyblue "重启后，请再次选择这个选项完成bbr2剩余部分安装(开启bbr和ECN)"
            tyblue "目前已知支持bbr2系统：Ubuntu16.04 —— 19.10、Debian 8 9 10"
            red    "目前已知不支持bbr2系统：Ubuntu14.04 20.04"
            red    "警告：不支持的系统安装bbr2会导致系统崩溃(可正常安装bbr1)"
            yellow "按回车键以继续。。。。"
            read rubbish
            rm -rf bbr2.sh
            if ! wget https://github.com/yeyingorg/bbr2.sh/raw/master/bbr2.sh ; then
                red    "获取bbr2脚本失败"
                red    "你的服务器貌似没联网，或不支持ipv4"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x bbr2.sh
            ./bbr2.sh
            ;;
        3)
            tyblue "****即将安装bbr2加速，安装完成后服务器将会重启，重启后，请再次运行此脚本完成剩余安装****"
            yellow "按回车键以继续。。。。"
            read rubbish
            rm -rf bbr2.sh
            if ! wget https://github.com/jackjieYYY/bbr2/raw/master/bbr2.sh ; then
                red    "获取bbr2脚本失败"
                yellow "你的服务器貌似没联网，或不支持ipv4"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x bbr2.sh
            ./bbr2.sh
            ;;
    esac
}


#配置sshd
setsshd()
{
    tyblue "*****************************************"
    tyblue "安装可能需要比较长的时间(5-40分钟)"
    tyblue "如果和ssh断开连接将会很麻烦"
    tyblue "设置ssh连接超时时间将大大降低断连可能性"
    yellow "注：升级系统后ssh配置文件将会恢复默认"
    tyblue "*****************************************"
    ifsetsshd=9
    while [ "$ifsetsshd" != "y" -a "$ifsetsshd" != "n" ]
    do
        tyblue "是否设置ssh连接超时时间？(y/n)"
        read ifsetsshd
    done
    case "$ifsetsshd" in
        y)
            echo "ClientAliveInterval 30" >> /etc/ssh/sshd_config
            echo "ClientAliveCountMax 60" >> /etc/ssh/sshd_config
            echo "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" >> /etc/ssh/sshd_config
            service sshd restart
            green  "**********************配置完成**********************"
            tyblue "请重新进行ssh连接，然后再次运行此脚本"
            yellow "按回车键退出。。。。"
            read asfyerbsd
            exit
            ;;
        n)
            ;;
    esac
}


#获取证书
get_certs()
{
    cp /etc/nginx/conf/nginx.conf.default /etc/nginx/conf/nginx.conf
    /etc/nginx/sbin/nginx -s stop
    sleep 1s
    /etc/nginx/sbin/nginx
    case "$domainconfig" in
        1)
            ~/.acme.sh/acme.sh --issue -d $domain -d www.$domain --webroot /etc/nginx/html -k ec-256
            ;;
        2)
            ~/.acme.sh/acme.sh --issue -d $domain --webroot /etc/nginx/html -k ec-256
            ;;
    esac
    ~/.acme.sh/acme.sh --installcert -d $domain --key-file /etc/nginx/certs/$domain.key --fullchain-file /etc/nginx/certs/$domain.cer --ecc
    /etc/nginx/sbin/nginx -s stop
}


##下载网站模板，用于伪装
get_web()
{
    rm -rf /etc/nginx/html/$domain
    mkdir /etc/nginx/html/$domain
    if ! wget -P /etc/nginx/html/$domain https://github.com/kirin10000/v2ray-WebSocket-TLS-Web-setup-script/raw/master/Website-Template.zip ; then
        red    "获取网站模板失败"
        red    "你的服务器貌似没联网，或不支持ipv4"
        yellow "按回车键继续或者按ctrl+c终止"
        read rubbish
    fi
    unzip -q -d /etc/nginx/html/$domain /etc/nginx/html/$domain/*.zip
    rm -rf /etc/nginx/html/$domain/*.zip
}


#安装程序主体
install_v2ray_ws_tls()
{
    if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/ssh/sshd_config ; then
        setsshd
    fi
    remove_v2ray_nginx
    apt update -y
    uninstall_firewall
    doupdate
    uninstall_firewall
    install_bbr
    rm -rf bbr.sh
    rm -rf bbr2.sh
    rm -rf install_bbr.log*
    readDomain                                                                                      #读取域名
    readTlsConfig
    yum install -y gperftools-devel libatomic_ops-devel pcre-devel zlib-devel libxslt-devel gd-devel perl-ExtUtils-Embed geoip-devel lksctp-tools-devel libxml2-devel gcc gcc-c++ wget unzip curl                   ##libxml2-devel非必须
    apt install -y libgoogle-perftools-dev libatomic-ops-dev libperl-dev libxslt-dev zlib1g-dev libpcre3-dev libgeoip-dev libgd-dev libxml2-dev libsctp-dev g++ wget gcc unzip curl                                          ##libxml2-dev非必须
    apt autoremove -y
    yum autoremove -y
    apt clean
    yum clean all


##安装nginx
    rm -rf nginx-1.17.7.tar.gz
    rm -rf openssl-1.1.1d.tar.gz
    rm -rf openssl-1.1.1d
    rm -rf nginx-1.17.7
    if ! wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz ; then
        red    "获取openssl失败"
        red    "你的服务器貌似没有联网呢"
        yellow "按回车键继续或者按ctrl+c终止"
        read rubbish
    fi
    tar -zxf openssl-1.1.1d.tar.gz
    wget https://nginx.org/download/nginx-1.17.7.tar.gz
    tar -zxf nginx-1.17.7.tar.gz
    cd nginx-1.17.7
    ./configure --prefix=/etc/nginx --with-openssl=../openssl-1.1.1d --with-openssl-opt="enable-tls1_3 enable-tls1_2 enable-tls1 enable-ssl enable-ssl2 enable-ssl3 enable-ec_nistp_64_gcc_128 shared threads zlib-dynamic sctp" --with-mail=dynamic --with-mail_ssl_module --with-stream=dynamic --with-stream_ssl_module --with-stream_realip_module --with-stream_geoip_module=dynamic --with-stream_ssl_preread_module --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-pcre --with-libatomic --with-compat --with-cpp_test_module --with-google_perftools_module --with-file-aio --with-threads --with-poll_module --with-select_module --with-cc='cc -O3' --with-cc-opt=-O3
    sed -i 's# -g # #' objs/Makefile                                                  ##关闭调试
    sed -i 's#CFLAGS="\$CFLAGS -g"#CFLAGS="\$CFLAGS"#' auto/cc/*                      ##关闭调试
    sed -i 's#CFLAGS="\$CFLAGS -g #CFLAGS="\$CFLAGS #' auto/cc/*                      ##关闭调试
    make
    make install
    mkdir /etc/nginx/certs
    mkdir /etc/nginx/conf.d
    cd ..
    rm -rf nginx-1.17.7.tar.gz
    rm -rf openssl-1.1.1d.tar.gz
    rm -rf openssl-1.1.1d
    rm -rf nginx-1.17.7
##安装nignx完成


    curl https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    get_certs
    if ! bash <(curl -L -s https://install.direct/go.sh) ; then
        red    "你的服务器貌似不支持ipv4"
        yellow "按回车键继续或者按ctrl+c终止"
        read rubbish
    fi


##获取端口、id和path
    path=$(cat /dev/urandom | head -c 8 | md5sum | head -c 6)               ##获取随机值作为path
    port=`grep port /etc/v2ray/config.json`
    port=${port##*' '}
    port=${port%%,*}
    v2id=`grep id /etc/v2ray/config.json`
    v2id=${v2id#*:}
##获取端口、id和path完成


    configtls                                                              ##配置nginx
    get_web


##配置v2ray文件
    sed -i 's/"protocol"/"listen": "127.0.0.1",\n    &/' /etc/v2ray/config.json
    sed -i 's/"alterId": 64/"alterId": 0/' /etc/v2ray/config.json
    hang=`sed -n '/"outbounds"/=' /etc/v2ray/config.json`
    hang=$(($hang+1))
    hanglast=`sed -n '$=' /etc/v2ray/config.json`
    sed -i "${hang},${hanglast}d" /etc/v2ray/config.json
    echo '    "protocol": "freedom",' >> /etc/v2ray/config.json
    echo '    "settings": {}' >> /etc/v2ray/config.json
    echo '  }]' >> /etc/v2ray/config.json
    echo '}' >> /etc/v2ray/config.json
    sed -i 's#}],#,"streamSettings":{"network"#' /etc/v2ray/config.json
    sed -i 's#"network"#&:"ws","wsSettings":{"pa#' /etc/v2ray/config.json
    sed -i s#gs\":{\"pa#\&th\":\"/$path\"}}}],# /etc/v2ray/config.json
##配置v2ray文件完成


    service v2ray restart
    /etc/nginx/sbin/nginx
    case "$domainconfig" in
        1)
            clear
            tyblue "*************安装完成*************"
            tyblue "地址：www.${domain}或${domain}"
            tyblue "端口：443"
            tyblue "ID：${v2id}"
            tyblue "额外ID：0"
            tyblue "加密方式：任意(推荐：none)"
            tyblue "传输协议：ws"
            tyblue "伪装类型：none"
            tyblue "伪装域名：空"
            tyblue "路径：/${path}"
            tyblue "底层传输安全：tls"
            tyblue "**********************************"
            yellow "注意事项：如重新启动服务器，请执行/etc/nginx/sbin/nginx"
            echo
            tyblue "脚本最后更新时间：2020.1.21"
            echo
            red    "此脚本仅供交流学习使用，请勿使用此脚本行违法之事。网络非法外之地，行非法之事，必将接受法律制裁!!!!"
            tyblue "2019.11"
            ;;
        2)
            clear
            tyblue "*************安装完成*************"
            tyblue "地址：${domain}"
            tyblue "端口：443"
            tyblue "ID：${v2id}"
            tyblue "额外ID：0"
            tyblue "加密方式：任意(推荐：none)"
            tyblue "传输协议：ws"
            tyblue "伪装类型：none"
            tyblue "伪装域名：空"
            tyblue "路径：/${path}"
            tyblue "底层传输安全：tls"
            tyblue "**********************************"
            yellow "注意事项：如重新启动服务器，请执行/etc/nginx/sbin/nginx"
            echo
            tyblue "脚本最后更新时间：2020.1.21"
            echo
            red    "此脚本仅供交流学习使用，请勿使用此脚本行违法之事。网络非法外之地，行非法之事，必将接受法律制裁!!!!"
            tyblue "2019.11"
            ;;
    esac
}

#修改dns
change_dns()
{
    red "ubuntu系统重启后会恢复原dns！！"
    tyblue "此操作将修改dns服务器为1.1.1.1和1.0.0.1(cloudflare dns)"
    if_change_dns="45"
    while [ "$if_change_dns" != "y" -a "$if_change_dns" != "n" ]
    do
        tyblue "是否要继续?(y/n)"
        read if_change_dns
    done
    if [ $if_change_dns == "y" ]; then
        if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/resolv.conf ; then
            sed -i 's/nameserver /#&/' /etc/resolv.conf
            echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
            echo 'nameserver 1.0.0.1' >> /etc/resolv.conf
            echo '#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script' >> /etc/resolv.conf
        fi
        green "修改完成！！"
    fi
}

#开始菜单
start_menu()
{
    stty erase '^H'
    clear
    tyblue "*****************************************************"
    tyblue "v2ray  WebSocket(ws)+TLS(1.3)+Web  搭建脚本"
    tyblue "脚本特性："
    tyblue "1.集成安装bbr(2)加速"
    tyblue "2.支持多种系统(ubuntu centos debian ...)"
    tyblue "3.集成TLS配置多版本安装选项"
    tyblue "4.集成删除防火墙、阿里云盾功能"
    tyblue "5.使用nginx作为网站服务"
    tyblue "6.使用acme.sh自动申请域名证书"
    tyblue "官网：https://github.com/kirin10000/v2ray-WebSocket-TLS-Web-setup-script"
    tyblue "*****************************************************"
    echo
    tyblue "*****************************************************"
    red    "此脚本需要一个解析到本服务器的域名!!!!"
    yellow "此脚本需要一个解析到本服务器的域名!!!!"
    tyblue "此脚本需要一个解析到本服务器的域名!!!!"
    red    "全程建议不要使用小键盘"
    yellow "全程建议不要使用小键盘"
    tyblue "推荐服务器系统使用ubuntu最新版"
    tyblue "*****************************************************"
    green  "1.安装v2ray-WebSocket(ws)+TLS(1.3)+Web(内含bbr安装选项)"
    red    "2.删除v2ray-WebSocket(ws)+TLS(1.3)+Web"
    tyblue "3.重启v2ray-WebSocket(ws)+TLS(1.3)+Web服务(对于玄学断连/掉速有奇效)"
    tyblue "4.重置域名和TLS配置(会覆盖原有域名配置，配置过程中域名输错了造成v2ray无法启动可以用此选项修复)"
    tyblue "5.添加域名(不同域名可以有不同的TLS配置)"
    tyblue "6.升级v2ray"
    tyblue "7.仅安装bbr(2)"
    tyblue "8.修改dns"
    yellow "9.退出脚本"
    echo
    menu="3345"
    while [ "$menu" != "1" -a "$menu" != "2" -a "$menu" != "3" -a "$menu" != "4" -a "$menu" != "5" -a "$menu" != "6" -a "$menu" != "7" -a "$menu" != "8" -a "$menu" != "9" ]
    do
        read -p "您的选择是：" menu
    done
    case "$menu" in
        1)
            install_v2ray_ws_tls
            ;;
        2)
            remove_v2ray_nginx
            green  "v2ray-WebSocket(ws)+TLS(1.3)+Web已删除"
            ;;
        3)
            /etc/nginx/sbin/nginx -s stop
            sleep 1s
            service v2ray restart
            /etc/nginx/sbin/nginx
            green  "重启完成"
            ;;
        4)
            readDomain
            readTlsConfig
            get_certs
            port=`grep port /etc/v2ray/config.json`
            port=${port##*' '}
            port=${port%%,*}
            path=`grep path /etc/v2ray/config.json`
            path=${path#*/}
            path=${path%'"'*}
            configtls
            get_web
            /etc/nginx/sbin/nginx
            green "重置域名完成！！"
            case "$domainconfig" in
                1)
                    green "服务器地址请填写www.${domain} 或 $domain"
                    ;;
                2)
                    green "服务器地址请填写$domain"
                    ;;
            esac
            ;;
        5)
            readDomain
            readTlsConfig
            get_certs
            port=`grep port /etc/v2ray/config.json`
            port=${port##*' '}
            port=${port%%,*}
            path=`grep path /etc/v2ray/config.json`
            path=${path#*/}
            path=${path%'"'*}
            new_tls
            get_web
            /etc/nginx/sbin/nginx
            green "添加域名完成！！"
            case "$domainconfig" in
                1)
                    green "现在服务器地址可以填写原来的域名和www.${domain} ${domain}"
                    ;;
                2)
                    green "现在服务器地址可以填写原来的域名和${domain}"
                    ;;
            esac
            ;;
        6)
            if ! bash <(curl -L -s https://install.direct/go.sh) ; then
                red    "你的服务器貌似没联网，或不支持ipv4，请检查网络连接"
                yellow "v2ray更新失败"
            fi
            ;;
        7)
            install_bbr
            rm -rf bbr.sh
            rm -rf bbr2.sh
            rm -rf install_bbr.log*
            ;;
        8)
            change_dns
            ;;
    esac
}


start_menu                                     ##从这里脚本开始执行
