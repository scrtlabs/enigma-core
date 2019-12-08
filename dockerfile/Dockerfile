# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.0.9

LABEL maintainer=enigmampc

WORKDIR /root

RUN rm -rf /root/sgx

# dependency for https://github.com/erickt/rust-zmq
RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev\
    && rm -rf /var/lib/apt/lists/*

RUN /root/.cargo/bin/rustup target add wasm32-unknown-unknown && \
    /root/.cargo/bin/cargo install bindgen cargo-audit && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git


# clone the rust-sgx-sdk baidu sdk
RUN git clone --depth 1  -b v1.0.9 https://github.com/baidu/rust-sgx-sdk.git  sgx


RUN git clone --depth 1 --branch v5.18.3 https://github.com/facebook/rocksdb.git rocksdb && \
    cd rocksdb && make install-shared -j7 && rm -rf /root/rocksdb

# this is done for a run-time linker, it creates the link and cache to the installed rocksdb
# (see http://man7.org/linux/man-pages/man8/ldconfig.8.html)
RUN ldconfig

RUN echo 'LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &' >> /root/.bashrc

# Add env variable for dynamic linking of rocksdb
# (see https://github.com/rust-rocksdb/rust-rocksdb/issues/217)
RUN echo 'export ROCKSDB_LIB_DIR=/usr/local/lib' >> /root/.bashrc
