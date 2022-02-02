#!/bin/bash
gcc_version="11.2.0"

main(){
  apt-get update
  apt-get install gcc -y
  gcc --version
  wget https://github.com/gcc-mirror/gcc/archive/refs/tags/releases/gcc-$gcc_version.tar.gz
  tar zxf gcc-$gcc_version.tgz
  mkdir gcc-build
  cd gcc-build
  ../gcc-$gcc_version/configure --prefix=/usr/local/gcc-$gcc_version --enable-checking=release --enable-languages=c,c++
  make && sudo make install
  gcc --version
}

main
