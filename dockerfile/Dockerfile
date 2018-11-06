# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804

MAINTAINER enigmampc

WORKDIR /root

RUN rm -rf /root/sgx

# clone the rust-sgx-sdk baidu sdk v1.0.0

RUN git clone https://github.com/baidu/rust-sgx-sdk.git sgx -b v1.0.4

# dependency for https://github.com/erickt/rust-zmq
RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN /root/.cargo/bin/rustup target add wasm32-unknown-unknown && rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git
RUN echo '/opt/intel/libsgx-enclave-common/aesm/aesm_service & &' >> /root/.bashrc
