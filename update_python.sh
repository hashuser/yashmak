#!/bin/bash
path=$(cd "$(dirname "$0")";pwd)
python_version="3.11.6"
python_main_version="3.11"
current_python_version=$(python$python_main_version -V)
current_python_version=${current_python_version: 7}
cpu_count=$(( $(cat /proc/cpuinfo |grep "processor"|wc -l) - 1 ))
if [[ $cpu_count -lt 1 ]]
then
        cpu_count="1"
fi

install_python(){
  apt-get update
  apt-get install libreadline-gplv2-dev -y
  apt-get install libncursesw5-dev -y
  apt-get install libssl-dev -y
  apt-get install libsqlite3-dev tk-dev -y
  apt-get install libgdbm-dev -y
  apt-get install libbz2-dev -y
  apt-get install zlib1g-dev -y
  apt-get install libffi-dev -y
  apt-get install liblzma-dev -y
  wget https://www.python.org/ftp/python/$python_version/Python-$python_version.tgz
  tar zxf Python-$python_version.tgz
  cd $path/Python-$python_version
  ./configure --prefix=/usr/local/python-$python_version --enable-optimizations
  make -j $cpu_count && make install
  rm /usr/bin/python$python_main_version
  ln -s /usr/local/python-$python_version/bin/python$python_main_version /usr/bin/python$python_main_version
  python$python_main_version -m pip install uvloop
  python$python_main_version -m pip install ntplib
  python$python_main_version -m pip install psutil
  python$python_main_version -V
  rm -rf $path/Python-$python_version
  rm -f $path/Python-$python_version.tgz
  systemctl restart Yashmak
}

main(){
array0=(${python_version//./ })     # Split at periods
rc0=$(echo ${array0[2]} | grep -o 'rc' || true)  # Extract 'rc' if exists
rc0_num=$(echo ${array0[2]#$rc0} | grep -o '[0-9]*$' || true)  # Extract rc number if exists
array0[2]=$(echo ${array0[2]} | grep -o '^[0-9]*')  # Strip non-numerical characters at beginning

array1=(${current_python_version//./ })
rc1=$(echo ${array1[2]} | grep -o 'rc' || true)
rc1_num=$(echo ${array1[2]#$rc1} | grep -o '[0-9]*$' || true)
array1[2]=$(echo ${array1[2]} | grep -o '^[0-9]*')

# Initial comparison of major, minor, and patch version
if [[ ${array0[0]} -gt ${array1[0]} ]] || 
   ([[ ${array0[0]} -eq ${array1[0]} ]] && [[ ${array0[1]} -gt ${array1[1]} ]]) || 
   ([[ ${array0[0]} -eq ${array1[0]} ]] && [[ ${array0[1]} -eq ${array1[1]} ]] && [[ ${array0[2]} -gt ${array1[2]} ]])
then
    echo "update required"
    install_python
else
    # Specific checks for 'rc' versions
    if [[ ${array0[2]} -eq ${array1[2]} ]] && [[ "$rc0" == "rc" ]] && 
       ([[ -z "$rc1" ]] || ([[ "$rc1" == "rc" ]] && [[ "$rc0_num" -gt "$rc1_num" ]]))
    then
        echo "update required"
        install_python
    else
        echo "up to date"
    fi
fi
}

main
