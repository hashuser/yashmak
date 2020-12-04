#!/bin/bash

port_exist_check(){
    if [[ 0 -ne `lsof -i:"$1" | wc -l` ]];then
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
    fi
}

acme(){
    domain=""
    port_exist_check 80
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-384 --force
    if [[ $? -eq 0 ]];then
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /etc/v2ray/v2ray.crt --keypath /etc/v2ray/v2ray.key --ecc
    fi
}

main(){
  acme
  reboot
}

main
