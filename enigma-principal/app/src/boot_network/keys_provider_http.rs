use std::{convert::TryInto, sync::Arc};

use enigma_tools_m::{
    primitives::km_primitives::{PrincipalMessage, PrincipalMessageType},
    utils::EthereumAddress,
};
use failure::Error;
use jsonrpc_http_server::{
    jsonrpc_core::{Error as ServerError, ErrorCode, IoHandler, Params, Value},
    ServerBuilder,
};
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};

use enigma_crypto::KeyPair;
use enigma_types::ContractAddress;
use epoch_u::{epoch_provider::EpochProvider, epoch_types::EpochState};
use esgx::keys_keeper_u::get_enc_state_keys;
use common_u::errors::RequestValueErr;

const METHOD_GET_STATE_KEYS: &str = "getStateKeys";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StringWrapper(pub String);

impl TryInto<Vec<u8>> for StringWrapper {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> { Ok(self.0.from_hex()?) }
}

impl TryInto<[u8; 65]> for StringWrapper {
    type Error = Error;

    fn try_into(self) -> Result<[u8; 65], Self::Error> {
        let bytes = self.0.from_hex()?;
        if bytes.len() != 65 {
            return Err(RequestValueErr {
                request: METHOD_GET_STATE_KEYS.to_string(),
                message: "Cannot create a 65 bytes array from mismatching mismatching size slice.".to_string(),
            }.into());
        }
        let mut slice: [u8; 65] = [0; 65];
        slice.copy_from_slice(&bytes);
        Ok(slice)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct StateKeyRequest {
    pub data: StringWrapper,
    pub sig: StringWrapper,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateKeyResponse {
    pub data: StringWrapper,
    pub sig: StringWrapper,
}

impl<H: ToHex> From<H> for StringWrapper {
    fn from(bytes: H) -> Self { StringWrapper(bytes.to_hex()) }
}

pub struct PrincipalHttpServer {
    epoch_provider: Arc<EpochProvider>,
    pub port: u16,
}

impl StateKeyRequest {
    pub fn get_data(&self) -> Result<Vec<u8>, Error> { Ok(self.data.0.from_hex()?) }

    pub fn get_sig(&self) -> Result<[u8; 65], Error> {
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&self.sig.0.from_hex()?);
        Ok(sig)
    }
}

impl PrincipalHttpServer {
    pub fn new(epoch_provider: Arc<EpochProvider>, port: u16) -> PrincipalHttpServer { PrincipalHttpServer { epoch_provider, port } }

    #[logfn(DEBUG)]
    fn find_epoch_contract_addresses(request: &StateKeyRequest, msg: &PrincipalMessage, epoch_state: &EpochState) -> Result<Vec<ContractAddress>, Error> {
        let image = msg.to_sign()?;
        let sig = request.get_sig()?;
        let worker = KeyPair::recover(&image, sig)?.address();
        println!("Searching contract addresses for recovered worker: {:?}", worker.to_vec());
        let addrs = epoch_state.get_contract_addresses(&worker.into())?;
        Ok(addrs)
    }

    #[logfn(DEBUG)]
    pub fn get_state_keys(epoch_provider: Arc<EpochProvider>, request: StateKeyRequest) -> Result<Value, Error> {
        println!("Got get_state_keys request: {:?}", request);
        let msg = PrincipalMessage::from_message(&request.get_data()?)?;
        let response = match msg.data {
            PrincipalMessageType::Request(Some(addrs)) => {
                println!("Found addresses in message: {:?}", addrs);
                get_enc_state_keys(*epoch_provider.eid, request, None)?
            }
            PrincipalMessageType::Request(None) => {
                println!("No addresses in message, reading from epoch state...");
                let epoch_state = epoch_provider.get_state()?;
                let epoch_addrs = Self::find_epoch_contract_addresses(&request, &msg, &epoch_state)?;
                get_enc_state_keys(*epoch_provider.eid, request, Some(&epoch_addrs))?
            }
            _ => return Err(RequestValueErr {
                request: METHOD_GET_STATE_KEYS.to_string(),
                message: "Request data not found in PrincipalMessage".to_string(),
            }.into()),
        };
        let response_data = serde_json::to_value(&response)?;
        Ok(response_data)
    }

    /// Endpoint for the get_state_keys method
    ///
    /// Example:
    /// curl -X POST --data '{"jsonrpc": "2.0", "method": "get_state_keys", "params": ["84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"]' -H "Content-Type: application/json" http://127.0.0.1:3040/
    #[logfn(INFO)]
    pub fn start(&self) {
        let mut io = IoHandler::default();
        let epoch_provider = Arc::clone(&self.epoch_provider);
        io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
            let epoch_provider = epoch_provider.clone();
            let request = params.parse::<StateKeyRequest>()?;
            let body = match Self::get_state_keys(epoch_provider, request) {
                Ok(body) => body,
                Err(err) => {
                    return Err(ServerError {
                        code: ErrorCode::InternalError,
                        message: format!("Unable to get keys: {:?}", err),
                        data: None,
                    });
                }
            };
            Ok(body)
        });
        let server =
            ServerBuilder::new(io).start_http(&format!("0.0.0.0:{}", self.port).parse().unwrap()).expect("Unable to start RPC server");
        println!("JSON-RPC HTTP server listening on port: {}", self.port);
        server.wait();
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    extern crate jsonrpc_test as test;

    use std::collections::HashMap;
    use std::thread;

    use rustc_hex::FromHex;
    use serde_json::error::ErrorCode::EofWhileParsingObject;
    use web3::types::{H160, U256};
    use web3::types::Bytes;

    use enigma_types::ContractAddress;
    use epoch_u::epoch_provider::test::setup_epoch_storage;
    use epoch_u::epoch_types::ConfirmedEpochState;
    use esgx::epoch_keeper_u::set_worker_params;
    use esgx::epoch_keeper_u::tests::get_worker_params;
    use esgx::general::init_enclave_wrapper;

    use super::*;

    // Data generated by an external client
    const REF_MSG: &str = "84a67072656669789e456e69676d61204d657373616765a46461746181a75265717565737491dc0020ccfd1454ccbacca9334acc92415f3bcc850919ccaaccc121cc9fccc7cccc7a74ccbd7a25cc8475ccbc677867cc89a67075626b6579dc00400d02ccb405ccd5213cccd27e5b2ecc86ccf75e5acc812dccf64a37007a3bccf5cca45c7809cc8bcc94ccf22b50ccea3817cc9915ccaeccf51bcc97cce9ccc70a707a05cc880c436accff02cc8919cc9960023fccf0cce7ccf8ccf6a269649c000000000000000000000001";
    const REF_SIG: &str = "c5a40ca148e1048075d189371c522b202ab24143224cac3700c4f95fa922e5872ebb8dd867650c265e6f51a6c831081e0b5c3c5bb5a858f2b89fad2fd4facc0e1c";
    const REF_RESPONSE: &str = "83a46461746181b1456e6372";
    const REF_WORKER: [u8; 20] = [143, 123, 253, 113, 133, 173, 215, 156, 68, 228, 91, 227, 191, 31, 114, 35, 142, 245, 179, 32];
    const REF_CONTRACT_ADDR: [u8; 32] = [253, 20, 84, 186, 169, 51, 74, 146, 65, 95, 59, 133, 9, 25, 170, 193, 33, 159, 199, 204, 122, 116, 189, 122, 37, 132, 117, 188, 103, 120, 103, 137];

    #[test]
    pub fn test_jsonrpc_get_state_keys() {
        setup_epoch_storage();
        let enclave = init_enclave_wrapper().unwrap();
        let rpc = {
            let mut io = IoHandler::new();
            let eid = enclave.geteid();
            io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
                let request = params.parse::<StateKeyRequest>().unwrap();
                let response = get_enc_state_keys(eid, request, None).unwrap();
                let response_data = serde_json::to_value(&response).unwrap();
                Ok(response_data)
            });
            test::Rpc::from(io)
        };
        let workers: Vec<[u8; 20]> = vec![REF_WORKER];
        let stakes: Vec<u64> = vec![10000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        let epoch_state = set_worker_params(enclave.geteid(), &worker_params, None).unwrap();
        for i in 0..5 {
            let response = rpc.request(METHOD_GET_STATE_KEYS, &(REF_MSG, REF_SIG));
            assert!(response.contains(REF_RESPONSE));
        }
        enclave.destroy();
    }

    #[test]
    pub fn test_find_epoch_contract_addresses() {
        let msg = REF_MSG.from_hex().unwrap();
        let request = StateKeyRequest { data: StringWrapper(msg.to_hex()), sig: StringWrapper(REF_SIG.to_string()) };
        let address = ContractAddress::from(REF_CONTRACT_ADDR);
        let mut selected_workers: HashMap<ContractAddress, H160> = HashMap::new();
        selected_workers.insert(address, H160(REF_WORKER));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });
        let seed = U256::from(1);
        let sig = Bytes::from(REF_SIG.from_hex().unwrap());
        let nonce = U256::from(0);
        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        let msg = PrincipalMessage::from_message(&request.get_data().unwrap()).unwrap();
        let results = PrincipalHttpServer::find_epoch_contract_addresses(&request, &msg, &epoch_state).unwrap();
        assert_eq!(results, vec![address])
    }
}
