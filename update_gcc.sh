#!/bin/bash
gcc_version="11.2.0"
path=$(cd "$(dirname "$0")";pwd)

main(){
  apt-get update
  apt-get install make -y
  apt-get install libgmp-dev -y
  apt-get install libmpfr-dev -y
  apt-get install libmpc-dev -y
  apt-get install flex -y
  apt-get install gcc -y
  apt-get install g++ -y
  gcc --version
  wget https://github.com/gcc-mirror/gcc/archive/refs/tags/releases/gcc-$gcc_version.tar.gz
  tar zxf gcc-$gcc_version.tar.gz
  rm -rf gcc-build
  mkdir $path/gcc-build
  cd $path/gcc-build
  $path/gcc-releases-gcc-$gcc_version/configure --prefix=/usr/local/gcc-$gcc_version --enable-checking=release --enable-languages=c,c++ --disable-multilib
  make && sudo make install
  gcc --version
}

main
