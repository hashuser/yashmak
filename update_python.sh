#!/bin/bash
path=$(cd "$(dirname "$0")";pwd)
python_version="3.9.10"
python_main_version="3.9"
current_python_version=$(python$python_main_version -V)
current_python_version=${current_python_version: 7}
cpu_count=$(( $(cat /proc/cpuinfo |grep "processor"|wc -l) - 1 ))
if [[ $cpu_count < "1" ]]
then
        cpu_count="1"
fi

main(){
if [[ $current_python_version > $python_version ]] || [[ $current_python_version == $python_version ]]
then
        echo "Python is up to date"
else
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
        sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_gcc.sh | bash
        wget https://www.python.org/ftp/python/$python_version/Python-$python_version.tgz
        tar zxf Python-$python_version.tgz
        cd $path/Python-$python_version
        ./configure --prefix=/usr/local/python-$python_version --enable-optimizations
        make -j $cpu_count && make install
        rm /usr/bin/python$python_main_version
        ln -s /usr/local/python-$python_version/bin/python$python_main_version /usr/bin/python$python_main_version
        python3.9 -m pip install dnspython
        python3.9 -m pip install uvloop
        python3.9 -m pip install ntplib
        python3.9 -m pip install psutil
        python$python_main_version -V
        systemctl restart Yashmak
        rm -rf $path/Python-$python_version
        rm -f $path/Python-$python_version.tgz
fi
}

main
