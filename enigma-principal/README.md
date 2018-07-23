# Enigma Principal Node

<img src="https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg?branch=principal-node-isan" />

* To see all of the options available once compiled cd into /bin and type
```
$./enigma_principal_app --info
```
<img src="https://image.ibb.co/i7ugUJ/cli.jpg" />

The Principal node is part of the Enigma node software stack. 
The Principal component  is responsible for emitting random numbers from within an enclave into the Enigma contract. 
Currently it is a centralized to maintain simplicity while testing and developing Core.

## Getting Started (With the Enigma Docker)


### Prerequisites

* [Same as Enigma-Core](https://github.com/enigmampc/enigma-core/blob/master/README.md)

### Build and Compile 

* run docker:

```
docker run --net="host" -v some/path/enigma-core/:/root/enigma-core -ti --device /dev/isgx enigma-core-image
```

* build the project 

```
cd enigma-core/enigma-principal
make JOBS=8
```

## Principal Node Modes 

### For more info check the screenshot above.

* Deploy the Enigma/Token contract from scratch 
```
$./enigma_principal_app --deploy 
```
* Connect to deployed Enigma contract.
```
$./enigma_principal_app
```
* Run mining simulation in the background to move blocks forward in time (can be combined in any situation).
```
$./enigma_principal_app --mine <mining interval in seconds>
```
### Run the tests (inside Docker)

* The CI is running an Ethereum network locally.
* If you wish to run the tests:
* run ganache on port 8545 
  
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

### Run the project

```
cd root/enigma-core/enigma-principal/bin
./enigma_principal_app [flags]
```

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


