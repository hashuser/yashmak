#!/bin/bash
path=$(cd "$(dirname "$0")";pwd)
cpu_count=$(( $(cat /proc/cpuinfo |grep "processor"|wc -l) - 1 ))
if [[ $cpu_count < "1" ]]
then
        cpu_count="1"
fi

main(){
  sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_gcc.sh | bash
  update-ca-certificates -f
  wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1l.tar.gz
  tar xzvf OpenSSL_1_1_1l.tar.gz
  cd $path/openssl-OpenSSL_1_1_1l
  ./config
  make -j $cpu_count && make install
  echo "/usr/local/lib" > /etc/ld.so.conf.d/libc.conf
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  echo "ca_certificate=/etc/ssl/certs/ca-certificates.crt" > /etc/wgetrc
  ldconfig
  openssl version
  rm -rf $path/openssl-OpenSSL_1_1_1l
  rm -f $path/OpenSSL_1_1_1l.tar.gz
}

main
