# Enigma Key Management Node

The Key Management node is part of the Enigma node software stack. The Key Management component is responsible for emitting random numbers from within an enclave into the Enigma contract. Currently, it uses a centralized design in order to maintain simplicity while testing and developing Core, but it will eventually move to a decentralized design matching the rest of the network.

<img src="https://drone.enigma.co/api/badges/enigmampc/enigma-core/status.svg?branch=develop" />

## JSON RPC Server
This module implements a [JSON-RPC 2.0](https://www.jsonrpc.org/specification_)-compliant server

This module implements the following methods:

## getStateKeys

Requests the private secret contract state keys. Only the worker node assigned to a given contract for the current epoch
is authorized to make this request. The Principal node's enclave keeps a sealed list of active worker for 
each epoch by formally verifying the `WorkerParameterized` event in 
[Enigma.sol](https://github.com/enigmampc/enigma-contract/blob/master/contracts/Enigma.sol).
The response contains an encrypted list of state keys.
The encryption method relies on a DH key exchange between the Principal node and the authorized worker node.

**Parameters**

- `data` (String) - The HEX string of a serialized KM [Message](https://github.com/enigmampc/enigma-core/blob/develop/enigma-tools-t/src/km_primitives.rs) struct. The Request data contains a list of secret contract addresses (`Vec<ContractAddress>`).
- `sig` (String) - The signature of the keccak256 hash of the serialized KM Message (`msg.to_message()`). This allows the Principal node to recover the worker's signer address. 

**Returns**

- `data` (String) - The HEX string of the encrypted KM Message Response. The Response data contains a list of secret contract address / state key tuples (`Vec<(ContractAddress, StateKey)>`).
- `sig`: (String) - The HEX string of the 

**Example**

```sh
// Request
curl -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id":1, "method":"get_state_keys", "params": {"data": "84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "workerSig": "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"}}'

// Result
{
	"jsonrpc":"2.0",
	"id": 1,
	"result": {
	    "data": "0061d93b5412c0c99c3c7867db13c4e13e51292bd52565d002ecf845bb0cfd8adfa5459173364ea8aff3fe24054cca88581f6c3c5e928097b9d4d47fce12ae47",
	    "sig": ""
	}
}
```
 
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

* Must have an Ethereum network running like Ganache. 

All of the parameters can be configured programatically, with flags passed to the binary app or with a config file. 
There are generally 2 types of configuration files and 1 important feature - **mining simulation**. 

### Key Management Logic configuration 

Responsible for all the logic of the app (i.e epoch size, polling interval etc.)

* Default location (enigma-principal/app/tests/principal_node/config/principal_test_config.json)

* The path parameter can be changed using the flag (use relative path to aboid docker/os conflicts)

```
--principal-config /some/path/some_config.json
```
### Deployment configuration - NOT for production

The Key Management Logic has to connect to the Enigma contract, In order to have this we must also implement the EnigmaToken contract. The Key Management Node can connect to an existing environment or to deploy everything by itself. 

* Default location (enigma-principal/app/tests/principal_node/config/deploy_config.json)

* To run the Key Management node with a time limit in seconds use the flag 

```
--time-to-live <number>
```

* To run the Key Management node in deploy mode add the flag 

```
--deploy
```

* The path parameter can be changed using the flag (use relative path to aboid docker/os conflicts)

```
--deploy-config /some/path/some_config.json
```

### Mining Simulation mode

The idea is that the Key Management node publishes a random number to the Enigma smart contract every X blocks (i.e epochs). 
If running a private network like Ganache, we need a way to simulate mining of blocks and control the rate. 
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

## Key Management Node Modes 

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
