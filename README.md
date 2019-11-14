# Enigma Core library 

| Service | Master | Develop |
|---------|--------|---------|
| CI Badge | [![Build Status](https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg)](https://drone.enigma.co/enigmampc/enigma-core) | [![Build Status](https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg?ref=/refs/heads/develop)](https://drone.enigma.co/enigmampc/enigma-core) |

Pure Rust Enclave && Untrusted in Rust. 
Core is part of the Enigma node software stack. The Core component as it's name suggests is responsible for the core operations. The core includes Remote Attestation (SGX SDK), Cryptography and execution of WASM secret contracts.


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

If the following error occurs then this is an open issue that will be solved.

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

### Simulation Mode

If you want to run this in a computer that doesn't support SGX you can run both `enigma-core` and `surface` in simulation mode.  
To do this, run `surface` with `--simulation`, then fire up the docker and run:   
```
$ cd enigma-core
$ make full-clean
$ export SGX_MODE=SW
$ make # Here you can add JOBS=N to pass on to cargo the number of jobs to run simultaneously.
```

### Principal Node 

[Principal Node README](https://github.com/enigmampc/enigma-core/blob/master/enigma-principal/README.md). 

TBD

### Installing

TBD  

## Deployment


## Built With

TBD

## Contributing
The `master` branch always contain the latest release, `develop` branch is used for continuous developing  
Tags will be used to signify releases.

### Pull Request
Every new feature or a bug fix will be presented in a pull request while it's a work in progress under the correct label.  
When finished change the label to `3 - Ready` for reviewing, every pull request is required to pass a code review from at least 1 member before merging.

### Issues
Please use the templates accordingly.
<br>

## Versioning

TBD 

## Troubleshooting

#### Errors while building with make 
##### 1. wrong sgx_tstd:
```
error[E0463]: can't find crate for `std`
  --> /root/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/xargo/sgx_tunittest/../../sgx_tunittest/src/lib.rs:88:1
```
* Temp Solution: 
```
rm -rf ~/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/xargo/
```
##### 1. wrong wasmi:
```
error[E0599]: no function or associated item named `new` found for type `std::ops::RangeInclusive<_>` in the current scope
    --> /root/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.76/src/de/impls.rs:2084:12
     |
2084 |         Ok(RangeInclusive::new(start, end))
     |            ^^^^^^^^^^^^^^^^^^^ function or associated item not found in `std::ops::RangeInclusive<_>`

```
* Temp Solution:  
```
rm -rf ~/.cargo/git/checkouts/rust-sgx-sdk-fc8771c5c45bde9a/378a4f0/samplecode/wasmi
```


## Authors

* **Enigma Team** - [enigma](https://enigma.co/)

## License

The Enigma Core is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

You should have received a [copy](LICENSE) of the GNU Affero General Public License along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Acknowledgements

Thanks to [Baidu X-Lab](https://github.com/BaiduXLab) for their great work on [Rust SGX SDK](https://github.com/baidu/rust-sgx-sdk).
