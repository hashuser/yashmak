#!/bin/bash
path=$(cd "$(dirname "$0")";pwd)

main(){
  curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_gcc.sh | bash
  update-ca-certificates -f
  wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1l.tar.gz
  tar xzvf OpenSSL_1_1_1l.tar.gz
  cd $path/openssl-OpenSSL_1_1_1l
  ./config
  make
  make install
  echo "/usr/local/lib" > /etc/ld.so.conf.d/libc.conf
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  echo "ca_certificate=/etc/ssl/certs/ca-certificates.crt" > /etc/wgetrc
  ldconfig
  openssl version
  rm -rf $path/openssl-OpenSSL_1_1_1l
  rm -f $path/OpenSSL_1_1_1l.tar.gz
}

main
