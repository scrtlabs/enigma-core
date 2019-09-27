#!/bin/bash

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

sleep 5 # give time to aesm_service to start

cd /root/enigma-core/app
. /opt/sgxsdk/environment && . /root/.cargo/env && RUST_BACKTRACE=1 ./target/debug/enigma-core-app -vv
