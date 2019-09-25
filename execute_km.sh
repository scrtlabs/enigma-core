#!/bin/bash

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

sleep 5 # give time to aesm_service to start

until [ -f /root/.enigma/principal-sign-addr.txt ]; do
    echo 'Sleeping for 10 seconds until principal-sign-addr will be exist'
    sleep 10;
done;

echo Found signing address $(cat /root/.enigma/principal-sign-addr.txt) 

# TODO CONFIG CONTRACT

cd /root/.enigma
rm -rf debug.log enigmacontract.txt enigmatokencontract.txt epoch state-keys

cd /root/enigma-principal/bin
. /opt/sgxsdk/environment && RUST_BACKTRACE=1 ./enigma-principal-app
