#!/bin/bash
openssl_version="1_1_1u"
path=$(cd "$(dirname "$0")";pwd)
cpu_count=$(( $(cat /proc/cpuinfo |grep "processor"|wc -l) - 1 ))
if [[ $cpu_count < "1" ]]
then
        cpu_count="1"
fi

main(){
  update-ca-certificates -f
  wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_$openssl_version.tar.gz
  tar xzvf OpenSSL_$openssl_version.tar.gz
  cd $path/openssl-OpenSSL_$openssl_version
  ./config
  make -j $cpu_count && make install
  echo "/usr/local/lib" > /etc/ld.so.conf.d/libc.conf
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  echo "ca_certificate=/etc/ssl/certs/ca-certificates.crt" > /etc/wgetrc
  ldconfig
  openssl version
  rm -rf $path/openssl-OpenSSL_$openssl_version
  rm -f $path/OpenSSL_$openssl_version.tar.gz
}

main
