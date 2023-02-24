#!/bin/bash

main(){
  sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_python.sh | bash
  sudo curl -L https://raw.githubusercontent.com/hashuser/yashmak/master/update_openssl.sh | bash
}

main
