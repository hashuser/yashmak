#!/bin/bash
main(){
  wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1i.tar.gz
  tar xzvf openssl-1.1.1i.tar.gz
  cd openssl-1.1.1i
  ./config
  make
  make install
  echo "/usr/lib" >> /etc/ld.so.conf.d/libc.conf
  ldconfig
  openssl version
}

main
