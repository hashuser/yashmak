#!/bin/bash
main(){
  update-ca-certificates -f
  wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1l.tar.gz
  tar xzvf openssl-OpenSSL_1_1_1l.tar
  cd openssl-OpenSSL_1_1_1l.tar
  ./config
  make
  make install
  echo "/usr/local/lib" > /etc/ld.so.conf.d/libc.conf
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  echo "ca_certificate=/etc/ssl/certs/ca-certificates.crt" > /etc/wgetrc
  ldconfig
  openssl version
}

main
