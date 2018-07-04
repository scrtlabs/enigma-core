# Enigma Core library 

<img src="https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg?branch=develop" />

Pure Rust Enclave && Untrusted in Rust. 
Core is part of the Enigma node software stack. The Core component as it's name suggests is responsible for the core operations. The core includes Remote Attestation (SGX SDK), Cryptography and the Ethereum EVM.


## Getting Started (With the Enigma Docker)


### Prerequisites

* [RUST-SGX-Intel SGX SDK 2.1.3 for Linux](https://github.com/baidu/rust-sgx-sdk) installed.
* clone this repo into /some/path/enigma-core.
* [Docker](https://docs.docker.com/install) - Install.

### Build and Compile 

* build the enigma docker image

```
 cd /some/path/enigma-core/dockerfile
 docker build -t enigma_core .
```

The output should look like that: 

```
Sending build context to Docker daemon  2.048kB
Step 1/7 : FROM baiduxlab/sgx-rust:1.0.0
 ---> 44a7928943e4
Step 2/7 : MAINTAINER enigmampc
 ---> Using cache
 ---> 2a1b994a20f4
Step 3/7 : WORKDIR /root
 ---> Using cache
 ---> 33fc66f979b8
Step 4/7 : RUN rm -rf /root/sgx
 ---> Using cache
 ---> da313d0a4471
Step 5/7 : RUN git clone https://github.com/baidu/rust-sgx-sdk.git sgx -b v1.0.0
 ---> Using cache
 ---> 704631bc2d68
Step 6/7 : RUN apt-get install -y libzmq3-dev
 ---> Using cache
 ---> 141b17bb1564
Step 7/7 : RUN echo '/opt/intel/sgxpsw/aesm/aesm_service &' >> /root/.bashrc
 ---> Using cache
 ---> cd6787969fd1
Successfully built cd6787969fd1
```
* run docker:

```
docker run -v /some/path/enigma-core/:/root/enigma-core -ti -p 5552:5552 --device /dev/isgx enigma_core
```

* build the project 

```
cd enigma-core/enigma-core
make 
```

If the following error ocures then this is an open issuen that will be solved.

```
error[E0463]: can't find crate for `std`
  --> /root/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/xargo/sgx_tunittest/../../sgx_tunittest/src/lib.rs:88:1
   |
88 | extern crate sgx_tstd as std;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ can't find crate

error: aborting due to previous error

For more information about this error, try `rustc --explain E0463`.
error: Could not compile `sgx_tunittest`.
```
check out [Troubleshooting](https://github.com/enigmampc/enigma-core/tree/develop#troubleshooting) and then make clean && make

 
### Run the tests (inside Docker)

* Build the project 
```
make
cd app/
```
Run the tests (no std)
```
cargo test
```
Run the test (with std)
```
cargo test -- --nocapture
```

### Run the project

```
cd root/enigma-core/enigma-core/bin
./app
```

### Testing with the Surface server

This is the server that accepts commands from the surface component. 
Currently its unit-test is #[ignored] simply because testing it requires manually sending requests and watching the output. 
For now there's a compatible [Python client provided](https://github.com/enigmampc/enigma-core/tree/develop/enigma-core/app/tests/surface_listener),
the unit-test can be found [here](https://github.com/enigmampc/enigma-core/blob/246dc727f3e5d54ffe039b0b880b7bfecbcd1d8e/enigma-core/app/src/networking/surface_server.rs#L152).

Running this test will require to 
* comment out #[ignore]
* running the tests with -- --nocapture
* using the Python client that mimics surface.

### Principal Node 

Has a seperate [trsuted + untrusted](https://github.com/enigmampc/enigma-core/tree/develop/enigma-principal). 
There is a 100% code [reuse](https://github.com/enigmampc/enigma-core/tree/develop/enigma-tools-t)

TBD

### Installing

TBD  

## Deployment


## Built With

TBD

## Contributing

TBD 

## Versioning

TBD 

## Troubleshooting

* Error while building with make 
```
error[E0463]: can't find crate for `std`
  --> /root/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/xargo/sgx_tunittest/../../sgx_tunittest/src/lib.rs:88:1
```
* Temp Solution: 
```
rm -rf /root/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/xargo/
```
## Authors

* **Enigma Team** - [enigma](https://enigma.co/)

## License

TBD
