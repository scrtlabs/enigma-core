# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804

MAINTAINER enigmampc

WORKDIR /root

RUN rm -rf /root/sgx

# dependency for https://github.com/erickt/rust-zmq
RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev clang \
    && rm -rf /var/lib/apt/lists/*
    
# fixes build errors that started appearing seemingly out of nowhere in dependencies:
# error[E0658]: const fn is unstable (see issue #53555)      
RUN rustup install nightly-2018-11-01
RUN rustup default nightly-2018-11-01

RUN /root/.cargo/bin/rustup target add wasm32-unknown-unknown && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git

# clone the rust-sgx-sdk baidu sdk v1.0.4
RUN git clone --depth 1  -b v1.0.4 https://github.com/baidu/rust-sgx-sdk.git  sgx

RUN git clone --depth 1 --branch v5.14.2 https://github.com/facebook/rocksdb.git rocksdb && \
    cd rocksdb && make install-shared && rm -rf /root/rocksdb

RUN echo '/opt/intel/libsgx-enclave-common/aesm/aesm_service &' >> /root/.bashrc
RUN echo 'export ROCKSDB_LIB_DIR=/usr/local/lib' >> /root/.bashrc
