#!/bin/bash
create_service(){
  touch $(cd "$(dirname "$0")";pwd)/Yashmak.service
  cat>$(cd "$(dirname "$0")";pwd)/Yashmak.service<<EOF
  [Unit]
  Description=Yashmak Network Service
  After=rc-local.service

  [Service]
  Type=simple
  User=root
  Group=root
  WorkingDirectory=$(cd "$(dirname "$0")";pwd)
  ExecStart=/usr/bin/python3.9 $(cd "$(dirname "$0")";pwd)/server.py
  LimitNOFILE=1048575
  Restart=always
  TasksMax=infinity

  [Install]
  WantedBy=multi-user.target
EOF
}

install_service(){
  echo "root  soft nofile 1048575" >> /etc/security/limits.conf
  echo "root  hard nofile 1048575" >> /etc/security/limits.conf
  mv $(cd "$(dirname "$0")";pwd)/Yashmak.service /etc/systemd/system/
  systemctl enable Yashmak.service
  systemctl start Yashmak.service
}

create_shortcut(){
  echo "alias Yashmak_config='vim $(cd "$(dirname "$0")";pwd)/config.json'">>~/.bashrc
  echo "alias Yashmak_blacklist='vim $(cd "$(dirname "$0")";pwd)/blacklist.json'">>~/.bashrc
  echo "alias Yashmak_uninstall='rm -r $(cd "$(dirname "$0")";pwd)'">>~/.bashrc
  reboot
}

system_config(){
  echo "net.core.default_qdisc = fq_codel" > /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_keepalive_time = 300" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_keepalive_intvl = 5" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_keepalive_probes = 3" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_moderate_rcvbuf = 1" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
  echo "net.core.somaxconn = 262114" >> /etc/sysctl.conf
  echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
  echo "net.ipv4.ip_default_ttl = 128" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_adv_win_scale = 3" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
  echo "net.nf_conntrack_max = 2000000" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_rmem = 4096 524288 12582912" >> /etc/sysctl.conf
  echo "net.core.rmem_default = 524288" >> /etc/sysctl.conf
  echo "net.core.rmem_max = 12582912" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_wmem = 4096 524288 12582912" >> /etc/sysctl.conf
  echo "net.core.wmem_default = 524288" >> /etc/sysctl.conf
  echo "net.core.wmem_max = 12582912" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_mem = 786432 1048576 26777216" >> /etc/sysctl.conf
  sysctl -p
  apt-get install resolvconf -y
  echo "dns-nameservers 1.1.1.1" >> /etc/network/interfaces
  /etc/init.d/networking restart
  /etc/init.d/resolvconf restart
}

sign_cert(){
  uuid=$(cat /proc/sys/kernel/random/uuid)
  uuid=${uuid:0:7}
  apt-get install openssl -y
  mkdir -p ./demoCA/{private,newcerts,conf}
  mkdir -p ./server/{private,request,conf}
  touch ./demoCA/index.txt
  touch ./demoCA/index.txt.attr
  touch ./demoCA/serial
  echo 01 > ./demoCA/serial
  wget -O ./demoCA/conf/ca.conf https://raw.githubusercontent.com/hashuser/yashmak/master/ca.conf
  wget -O ./server/conf/server.conf https://raw.githubusercontent.com/hashuser/yashmak/master/server.conf
  local_ipv4=`curl -4 ip.sb`
  if [ $? -ne 0 ]; then
    local_ipv6=`curl -6 ip.sb`
    if [ $? -ne 0 ]; then
      exit 1
    else
      echo "IP.1 = $local_ipv6" >> ./server/conf/server.conf
      sed -i "s/CN=GlobalSign/CN=$local_ipv6/" ./server/conf/server.conf
    fi
  else
    echo "IP.1 = $local_ipv4" >> ./server/conf/server.conf
    sed -i "s/CN=GlobalSign/CN=$local_ipv4/" ./server/conf/server.conf
    local_ipv6=`curl -6 ip.sb`
    if [ $? -eq 0 ]; then
      echo "IP.2 = $local_ipv6" >> ./server/conf/server.conf
    fi
  fi
  sed -i 's^RANDFILE		= $ENV::HOME/.rnd^# RANDFILE		= $ENV::HOME/.rnd^' /etc/ssl/openssl.cnf
  sed -i "s/O=Yashmak/O=$uuid/" ./demoCA/conf/ca.conf
  sed -i "s/O=Yashmak/O=$uuid/" ./server/conf/server.conf
  openssl ecparam -genkey -name prime256v1 -out ./demoCA/private/cakey.pem
  openssl ecparam -genkey -name prime256v1 -out ./server/private/server.key
  openssl req -new -x509 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem -days 7300 -config ./demoCA/conf/ca.conf
  openssl req -new -key ./server/private/server.key -out ./server/request/server.csr -config ./server/conf/server.conf
  openssl ca -batch -in ./server/request/server.csr -out ./server/server.crt -days 3650 -extensions req_ext -extfile ./server/conf/server.conf
  mkdir ./Certs
  mv ./demoCA/cacert.pem ./Certs
  mv ./server/private/server.key ./Certs
  mv ./server/server.crt ./Certs
  rm -rf ./demoCA
  rm -rf ./server
}

automatic_reboot(){
  apt-get install cron -y
  echo "0 16 * * * root systemctl restart Yashmak" >> /etc/crontab
  echo "0 16 * * 7 root reboot" >> /etc/crontab
  service cron restart
}

install_Yashmak(){
  mkdir $(cd "$(dirname "$0")";pwd)/Yashmak
  cd $(cd "$(dirname "$0")";pwd)/Yashmak
  mkdir ./Cache
  apt-get update
  dpkg-reconfigure libc6
  DEBIAN_FRONTEND=noninteractive dpkg --configure libssl1.1 
  DEBIAN_FRONTEND=noninteractive apt-get install -y libssl1.1
  apt-get install python3.9 -y
  apt-get install python3-pip -y
  apt-get install python3-distutils -y
  python3.9 -m pip install dnspython
  python3.9 -m pip install uvloop
  python3.9 -m pip install ntplib
  python3.9 -m pip install psutil
  wget -O server.py https://raw.githubusercontent.com/hashuser/yashmak/master/server.py
  wget -O geoip.json https://raw.githubusercontent.com/hashuser/yashmak/master/geoip.json
  wget -O blacklist.json https://raw.githubusercontent.com/hashuser/yashmak/master/blacklist.json
  wget -O hostlist.json https://raw.githubusercontent.com/hashuser/yashmak/master/hostlist.json
}

main(){
  install_Yashmak
  create_service
  install_service
  system_config
  sign_cert
  automatic_reboot
  create_shortcut
}

main
