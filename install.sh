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
  echo "alias Yashmak='vim $(cd "$(dirname "$0")";pwd)/config.json'">>~/.bashrc
  reboot
}

bbr(){
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
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
  service
  mv $(cd "$(dirname "$0")";pwd)/Yashmak.service /etc/systemd/system/
  systemctl enable Yashmak.service
  systemctl start Yashmak.service
  bbr
  conf
}

main
