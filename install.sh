#!/bin/bash
service(){
  touch $(cd "$(dirname "$0")";pwd)/Crack.service
  cat>$(cd "$(dirname "$0")";pwd)/Crack.service<<EOF
  [Unit]
  Description=Crack Network Service
  After=rc-local.service

  [Service]
  Type=simple
  User=root
  Group=root
  WorkingDirectory=$(cd "$(dirname "$0")";pwd)
  ExecStart=/usr/bin/python3.7 $(cd "$(dirname "$0")";pwd)/Server.py
  Restart=always
  TasksMax=infinity

  [Install]
  WantedBy=multi-user.target
EOF
}

conf(){
  echo "alias Crack='vim $(cd "$(dirname "$0")";pwd)/crack_server.conf'">>~/.bashrc
  reboot
}

bbr(){
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
}

main(){
  mkdir $(cd "$(dirname "$0")";pwd)/Crack
  cd $(cd "$(dirname "$0")";pwd)/Crack
  apt-get update
  dpkg-reconfigure libc6
  DEBIAN_FRONTEND=noninteractive dpkg --configure libssl1.1 
  DEBIAN_FRONTEND=noninteractive apt-get install -y libssl1.1
  apt-get install python3.7 -y
  wget -O Server.py https://raw.githubusercontent.com/breakwa2333/Crack/master/Server.py
  echo 4194304 > /proc/sys/kernel/pid_max
  echo 1000000 > /sys/fs/cgroup/pids/user.slice/user-1000.slice/pids.max
  service
  mv $(cd "$(dirname "$0")";pwd)/Crack.service /etc/systemd/system/
  systemctl enable Crack.service
  systemctl start Crack.service
  bbr
  conf
}

main
