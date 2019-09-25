#!/bin/bash

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

sleep 5 # give time to aesm_service to start

rm -rf /root/.enigma/principal-sign-addr.txt /root/.enigma/keypair.sealed

pushd /root/enigma-principal/bin
    . /opt/sgxsdk/environment && . /root/.cargo/env && RUST_BACKTRACE=1 ./enigma-principal-app -w
popd