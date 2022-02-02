#!/bin/bash
python_version="3.9.10"
python_main_version="3.9"

main(){
  apt-get update
  apt-get install libreadline-gplv2-dev
  apt-get install libncursesw5-dev
  apt-get install libssl-dev
  apt-get install libsqlite3-dev tk-dev
  apt-get install libgdbm-dev
  apt-get install libbz2-dev
  apt-get install zlib1g-dev
  apt-get install libffi-dev
  apt-get install liblzma-dev
  apt-get install gcc
  gcc --version
  wget https://www.python.org/ftp/python/$python_version/Python-$python_version.tgz
  tar zxf Python-$python_version.tgz
  cd Python-$python_version
  ./configure --prefix=/usr/local/python-$python_version --enable-optimizations
  make && sudo make install
  rm /usr/bin/python$python_main_version
  ln -s /usr/local/python-$python_version/bin/python$python_main_version /usr/bin/python$python_main_version
  python$python_main_version -V
}

main
