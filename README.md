# Enigma Core library 

Pure Rust Enclave && Untrusted in Rust. 
Core is part of the Enigma node software stack. The Core component as it's name suggests is responsible for the core operations. The core includes Remote Attestation (SGX SDK), Cryptography and the Ethereum EVM.

## Getting Started

### Prerequisites

* [Intel SPID](https://software.intel.com/en-us/articles/certificate-requirements-for-intel-attestation-services) - Register to get an Unlinkable certificate + SPID (FOR REMOTE ATTESTATION ONLY)
* [RUST-SGX-SDK](https://github.com/baidu/rust-sgx-sdk/blob/master/documents/sgxtime.md) - follow the instalation rules
* clone this repo into /some/path/enigma-core
* run docker 
``` 
 docker run -v baidu/sdk/repo/path/rust-sgx-sdk/:/root/sgx -v /some/pathenigma-core:/root/enigma-core -v -ti --device /dev/isgx baiduxlab/sgx-rust
```
* Inside docker: 
```
 /opt/intel/sgxpsw/aesm/aesm_service &
 ```

```
cd /root/enigma-core
```

```
make
```

```
cd bin/
```

* Run the binary 

```
./app
```


### Installing

TBD  


## Running the tests

* Build the project 
```
make
``` 
```
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
