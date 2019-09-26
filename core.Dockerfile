FROM enigmampc/enigma-core-base

LABEL maintainer=enigmampc

ARG SGX_MODE

ENV SGX_MODE=${SGX_MODE:-SW}

# COPY . .
ADD ./eng-wasm/ ./eng-wasm
ADD ./enigma-core/ ./enigma-core
ADD ./enigma-crypto/ ./enigma-crypto
ADD ./enigma-principal/ ./enigma-principal
ADD ./enigma-runtime-t/ ./enigma-runtime-t
ADD ./enigma-tools-m/ ./enigma-tools-m
ADD ./enigma-tools-t/ ./enigma-tools-t
ADD ./enigma-tools-u/ ./enigma-tools-u
ADD ./enigma-types/ ./enigma-types
ADD ./examples ./examples

WORKDIR /root/enigma-core

RUN . /opt/sgxsdk/environment && env && make full-clean

RUN . /opt/sgxsdk/environment && env && SGX_MODE=${SGX_MODE} RUSTFLAGS=-Awarnings RUST_BACKTRACE=1 make DEBUG=1

RUN mkdir -p $HOME/.enigma 

WORKDIR /root

ADD ./execute_core.sh ./

EXPOSE 5552

CMD ["./execute_core.sh"]