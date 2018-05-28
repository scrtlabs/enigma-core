# Enigma Core library 

Pure Rust Enclave && Untrusted in Rust. 


### Prerequisites

* [Intel SPID](https://software.intel.com/en-us/articles/certificate-requirements-for-intel-attestation-services) - Register to get an Unlinkable certificate + SPID (FOR REMOTE ATTESTATION ONLY)
* [RUST-SGX-SDK](https://github.com/baidu/rust-sgx-sdk/blob/master/documents/sgxtime.md) - follow the instalation rules
* clone this repo into /some/path/enigma-core
* Initialize the submodules: `git submodule update --init`
* run docker 
``` 
 docker run -v baidu/sdk/repo/path/rust-sgx-sdk/:/root/sgx -v /some/pathenigma-core:/root/enigma-core -v -ti --device /dev/isgx baiduxlab/sgx-rust
```
* Inside docker: 
```
 /opt/intel/sgxpsw/aesm/aesm_service &
cd /root/enigma-core
make
cd bin/
```
* Run the binary 

```
./app
```