#!/bin/bash
service(){
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
  ExecStart=/usr/bin/python3.8 $(cd "$(dirname "$0")";pwd)/server.py
  Restart=always
  TasksMax=infinity

  [Install]
  WantedBy=multi-user.target
EOF
}

conf(){
  echo "alias Yashmak_config='vim $(cd "$(dirname "$0")";pwd)/config.json'">>~/.bashrc
  echo "alias Yashmak_uninstall='rm -r $(cd "$(dirname "$0")";pwd)'">>~/.bashrc
  reboot
}

bbr(){
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
}

cert(){
  uuid=$(cat /proc/sys/kernel/random/uuid)
  uuid=${uuid:0:7}
  apt-get install openssl
  mkdir -p ./demoCA/{private,newcerts,conf}
  mkdir -p ./server/{private,request,conf}
  touch ./demoCA/index.txt
  touch ./demoCA/index.txt.attr
  touch ./demoCA/serial
  echo 01 > ./demoCA/serial
  wget -O ./demoCA/conf/ca.conf https://raw.githubusercontent.com/hashuser/yashmak/master/ca.conf
  wget -O ./server/conf/server.conf https://raw.githubusercontent.com/hashuser/yashmak/master/server.conf
  local_ip=`curl -4 ip.sb`
  echo "IP.1 = $local_ip" >> ./server/conf/server.conf
  sed -i '/$ENV::HOME/.rnd/'d /etc/ssl/openssl.cnf
  sed -i 's/O=Yashmak/O=$uuid/' ./demoCA/conf/ca.conf
  sed -i 's/CN=GlobalSign/CN=$local_ip/' ./server/conf/server.conf
  sed -i 's/O=Yashmak/O=$uuid/' ./server/conf/server.conf
  openssl ecparam -genkey -name prime256v1 -out ./demoCA/private/cakey.pem
  openssl ecparam -genkey -name prime256v1 -out ./server/private/server.key
  openssl req -new -x509 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem -days 7300 -config ./demoCA/conf/ca.conf
  openssl req -new -key ./server/private/server.key -out ./server/request/server.csr -config ./server/conf/server.conf
  openssl ca -in ./server/request/server.csr -out ./server/server.crt -days 3650 -extensions req_ext -extfile ./server/conf/server.conf
}

main(){
  mkdir $(cd "$(dirname "$0")";pwd)/Yashmak
  cd $(cd "$(dirname "$0")";pwd)/Yashmak
  apt-get update
  dpkg-reconfigure libc6
  DEBIAN_FRONTEND=noninteractive dpkg --configure libssl1.1 
  DEBIAN_FRONTEND=noninteractive apt-get install -y libssl1.1
  apt-get install python3.8 -y
  wget -O server.py https://raw.githubusercontent.com/hashuser/yashmak/master/server.py
  wget -O common.txt https://raw.githubusercontent.com/hashuser/yashmak/master/common.txt
  wget -O geoip.txt https://raw.githubusercontent.com/hashuser/yashmak/master/geoip.txt
  service
  mv $(cd "$(dirname "$0")";pwd)/Yashmak.service /etc/systemd/system/
  systemctl enable Yashmak.service
  systemctl start Yashmak.service
  bbr
  cert
  conf
}

main
