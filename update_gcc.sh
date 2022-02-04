#!/bin/bash
gcc_version="11.2.0"
path=$(cd "$(dirname "$0")";pwd)
current_gcc_version=$(gcc -dumpversion)
current_gpp_version=$(g++ -dumpversion)
cpu_count=$(( $(cat /proc/cpuinfo |grep "processor"|wc -l) - 1 ))
if [[ $cpu_count < "1" ]]
then
        cpu_count="1"
fi

array0=(${gcc_version//./ })
array1=(${current_gcc_version//./ })

if [[ $((${array0[0]})) -gt $((${array1[0]})) ]]
then
        echo "update required $((${array0[0]})) $((${array1[0]}))"
elif [[ $((${array0[0]})) -eq $((${array1[0]})) ]]
then
        if [[ $((${array0[1]})) -gt $((${array1[1]})) ]]
        then
                echo "update required $((${array0[1]})) $((${array1[1]}))"
        elif [[ $((${array0[1]})) -eq $((${array1[1]})) ]]
        then
                if [[ $((${array0[2]})) -gt $((${array1[2]})) ]]
                then
                        echo "update required"
                else
                        echo "up to date"
                fi
        else
                echo "up to date"
        fi
else
        echo "up to date"
fi

main(){
  if [[ $current_gcc_version > $gcc_version && $current_gpp_version > $gcc_version ]] || [[ $current_gcc_version == $gcc_version && $current_gpp_version == $gcc_version ]]
  then
          echo "GCC is up to date"
  else
          apt-get update
          apt-get install make -y
          apt-get install libgmp-dev -y
          apt-get install libmpfr-dev -y
          apt-get install libmpc-dev -y
          apt-get install flex -y
          apt-get install gcc -y
          apt-get install g++ -y
          gcc --version
          rm -rf gcc-build
          rm -rf gcc-releases-gcc-$gcc_version
          rm -f gcc-$gcc_version.tar.gz
          wget https://github.com/gcc-mirror/gcc/archive/refs/tags/releases/gcc-$gcc_version.tar.gz
          tar zxf gcc-$gcc_version.tar.gz
          mkdir $path/gcc-build
          cd $path/gcc-build
          $path/gcc-releases-gcc-$gcc_version/configure --prefix=/usr/local/gcc-$gcc_version --enable-checking=release --enable-languages=c,c++ --disable-multilib
          make -j $cpu_count && make install
          gcc --version
          update-alternatives --remove gcc /usr/bin/gcc-$gcc_version/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-$gcc_version/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-11.1.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-11.1.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-10.3.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-10.3.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-10.2.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-10.2.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-10.1.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-10.1.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-9.4.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-9.4.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-9.3.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-9.3.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-9.2.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-9.2.0/bin/g++
          update-alternatives --remove gcc /usr/bin/gcc-9.1.0/bin/gcc
          update-alternatives --remove g++ /usr/bin/gcc-9.1.0/bin/g++
          update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$gcc_version/bin/gcc 50
          update-alternatives --install /usr/bin/g++ g++ /usr/bin/gcc-$gcc_version/bin/g++ 50
          rm -rf gcc-build
          rm -rf gcc-releases-gcc-$gcc_version
          rm -f gcc-$gcc_version.tar.gz
fi
}

main
