#!/bin/bash
python_main_version="3.10"

create_service(){
  touch $(cd "$(dirname "$0")";pwd)/Yashmak_client.service
  cat>$(cd "$(dirname "$0")";pwd)/Yashmak_client.service<<EOF
  [Unit]
  Description=Yashmak (Client) Network Service
  After=rc-local.service

  [Service]
  Type=simple
  User=root
  Group=root
  WorkingDirectory=$(cd "$(dirname "$0")";pwd)
  ExecStart=/usr/bin/python$python_main_version $(cd "$(dirname "$0")";pwd)/local.py
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
  mv $(cd "$(dirname "$0")";pwd)/Yashmak_client.service /etc/systemd/system/
  systemctl enable Yashmak_client.service
  systemctl start Yashmak_client.service
}

create_shortcut(){
  echo "alias Yashmak_client_config='vim $(cd "$(dirname "$0")";pwd)/config.json'">>~/.bashrc
  echo "alias Yashmak_client_uninstall='rm -r $(cd "$(dirname "$0")";pwd)'">>~/.bashrc
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
  echo "dns-nameservers 114.114.114.114" >> /etc/network/interfaces
  /etc/init.d/networking restart
  /etc/init.d/resolvconf restart
}

automatic_reboot(){
  apt-get install cron -y
  echo "0 0 * * * root systemctl restart Yashmak_client" >> /etc/crontab
  echo "0 0 * * 7 root reboot" >> /etc/crontab
  service cron restart
}

install_Yashmak(){
  mkdir $(cd "$(dirname "$0")";pwd)/Yashmak_client
  cd $(cd "$(dirname "$0")";pwd)/Yashmak_client
  mkdir ./Config
  mkdir ./Config/Certs
  mkdir ./Config/Backup
  apt-get update
  dpkg-reconfigure libc6
  DEBIAN_FRONTEND=noninteractive dpkg --configure libssl1.1 
  DEBIAN_FRONTEND=noninteractive apt-get install -y libssl1.1
  apt-get install python$python_main_version -y
  apt-get install python3-pip -y
  apt-get install python3-distutils -y
  python$python_main_version -m pip install aioprocessing
  python$python_main_version -m pip install pycryptodome
  python$python_main_version -m pip install psutil
  wget -O local.py https://raw.githubusercontent.com/hashuser/yashmak/master/local.py
  echo "[]" > Config/HSTS2.json
  echo "[]" > Config/EXURL.json
  echo "[]" > Config/exception.json
  echo "{}" > Config/config.json
  wget -O Config/geoip.json https://raw.githubusercontent.com/hashuser/yashmak/master/geoip.json
  wget -O Config/chinalist.json https://raw.githubusercontent.com/hashuser/yashmak/master/chinalist.json
}

main(){
  install_Yashmak
  create_service
  install_service
  system_config
  automatic_reboot
  create_shortcut
}

main
