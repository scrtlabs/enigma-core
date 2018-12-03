# Enigma Principal Node

The Principal node is part of the Enigma node software stack. 
The Principal component  is responsible for emitting random numbers from within an enclave into the Enigma contract. 
Currently it is a centralized to maintain simplicity while testing and developing Core.

<img src="https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg?branch=principal-node-isan" />

## To see all of the options available once compiled cd into /bin and type
```
$./enigma_principal_app --info
```
<img src="https://image.ibb.co/nOcLry/newinfo.png" />

## Running in mining simulation mode
```
$./enigma_principal_app --deploy --mine <number: create blocks rate/seconds>
```
<img src="https://image.ibb.co/hunpJd/mininig.png" />

## Configuration

* Must have an ethereum network on like ganache. 

All of the parameters can be configured programatically, with flags passed to the binary app or with config file. 
There are generally 2 types of configuration files and 1 important feature - **mining simulation**. 

### Principal Logic configuration 

Responsible for all the logic of the app (i.e epoch size, polling interval etc.)

* Default location (enigma-principal/app/tests/principal_node/config/principal_test_config.json)

* The path parameter can be changed using the flag (use relative path to aboid docker/os conflicts)

```
--principal-config /some/path/some_config.json
```
### Deployment configuration - NOT for production

The Principal Logic has to connect to the Enigma contract, In order to have this we must also implement the EnigmaToken contract.
The Principal Node can connect to an existing environment or to deploy everything by itself. 

* Default location (enigma-principal/app/tests/principal_node/config/deploy_config.json)

* To run the principal node with a time limit in seconds use the flag 

```
--time-to-live <number>
```

* To run the Pricipal in deploy mode add the flag 

```
--deploy
```

* The path parameter can be changed using the flag (use relative path to aboid docker/os conflicts)

```
--deploy-config /some/path/some_config.json
```

### Mining Simulation mode

The idea is that the principal node publishes a random number to the Enigma smart contract every X blocks (i.e epochs). 
If running a private network like ganache we need a way to simulate mining of blocks and control the rate. 
The mining mode will submit a new blocks as defined to the network and it does not depend on whether the contracts were deployed by this app or not. 

* To run the mining simulation and create a new block every 2 seconds one should type: 

``` 
--mine 2
```

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

0.1

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


