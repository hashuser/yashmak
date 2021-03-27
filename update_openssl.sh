#!/bin/bash
main(){
  update-ca-certificates -f
  wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1j.tar.gz
  tar xzvf openssl-1.1.1j.tar.gz
  cd openssl-1.1.1j
  ./config
  make
  make install
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  ldconfig
  openssl version
}

main
