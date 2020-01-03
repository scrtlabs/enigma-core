use std::{convert::TryInto, sync::Arc};

use enigma_tools_m::{
    primitives::km_primitives::PrincipalMessage,
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
use enigma_types::{ContractAddress, EnclaveReturn};
use enigma_tools_u::web3_utils::enigma_contract::ContractQueries;
use epoch_u::{epoch_provider::EpochProvider, epoch_types::EpochState};
use esgx::keys_keeper_u::get_enc_state_keys;
use esgx;
use common_u::errors::{RequestValueErr, EnclaveFailError, EpochStateTransitionErr, JSON_RPC_ERROR_ILLEGAL_STATE, JSON_RPC_ERROR_WORKER_NOT_AUTHORIZED};
use web3::types::{U256, H160};


const METHOD_GET_STATE_KEYS: &str = "getStateKeys";
const METHOD_GET_HEALTH_CHECK: &str = "getHealthCheck";

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
                message: format!("Cannot create a 65 bytes array from a {} size slice.", bytes.len()),
            }.into());
        }
        let mut slice: [u8; 65] = [0; 65];
        slice.copy_from_slice(&bytes);
        Ok(slice)
    }
}

impl TryInto<U256> for StringWrapper {
    type Error = Error;

    fn try_into(self) -> Result<U256, Self::Error> {
        let result = U256::from_dec_str(&self.0);
        if let Ok(v) = result {
            Ok(v)
        } else {
            Err(RequestValueErr {
                request: METHOD_GET_STATE_KEYS.to_string(),
                message: "Cannot create a number.".to_string(),
            }.into())
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct StateKeyRequest {
    pub data: StringWrapper,
    pub sig: StringWrapper,
    pub block_number: Option<StringWrapper>,
    pub addresses: Option<Vec<String>>,
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
        self.sig.clone().try_into()
    }
}

impl PrincipalHttpServer {
    pub fn new(epoch_provider: Arc<EpochProvider>, port: u16) -> PrincipalHttpServer { PrincipalHttpServer { epoch_provider, port } }

    #[logfn(DEBUG)]
    fn find_epoch_contract_addresses(request: &StateKeyRequest, msg: &PrincipalMessage, epoch_state: &EpochState) -> Result<Vec<ContractAddress>, Error> {
        let image = msg.to_sign()?;
        let sig = request.get_sig()?;
        let worker = KeyPair::recover(&image, sig)?.address();
        trace!("Searching contract addresses for recovered worker: {:?}", worker.to_vec());
        let addrs = epoch_state.get_contract_addresses(&worker.into())?;
        Ok(addrs)
    }

    #[logfn(DEBUG)]
    pub fn get_state_keys(epoch_provider: &EpochProvider, request: StateKeyRequest) -> Result<Value, Error> {
        let epoch_state = match request.block_number.clone() {
            Some(block_number) => epoch_provider.find_epoch(block_number.try_into()?)?,
            None => epoch_provider.find_last_epoch()?,
        };
        let addresses = &request.addresses;
        let addrs: Vec<ContractAddress> = {
            if let Some(addrs) = addresses {
                let res: Result<Vec<ContractAddress>, _>  = addrs.iter().map(|item| ContractAddress::from_hex(item)).collect();
                res?
            }
            else{
                let msg = PrincipalMessage::from_message(&request.get_data()?)?;
                Self::find_epoch_contract_addresses(&request, &msg, &epoch_state)?
            }
        };
        let response = get_enc_state_keys(*epoch_provider.eid, request, epoch_state.nonce, &addrs)?;
        let response_data = serde_json::to_value(&response)?;
        Ok(response_data)
    }

    fn handle_error(internal_err: Error) -> ServerError {
        if let Some(err) = internal_err.downcast_ref::<EnclaveFailError>() {
            error!("{:?}", internal_err.as_fail());
            let server_err = match &err.err {
                EnclaveReturn::WorkerAuthError => {
                    ServerError {
                        code: ErrorCode::ServerError(JSON_RPC_ERROR_WORKER_NOT_AUTHORIZED),
                        message: format!("Worker not authorized to request the keys: {:?}.", err),
                        data: None,
                    }
                }
                _ => {
                    ServerError {
                        code: ErrorCode::InternalError,
                        message: format!("Internal error in enclave: {:?}", err),
                        data: None,
                    }
                }
            };
            return server_err;
        }
        if let Some(err) = internal_err.downcast_ref::<EpochStateTransitionErr>() {
            return ServerError {
                code: ErrorCode::ServerError(JSON_RPC_ERROR_ILLEGAL_STATE),
                message: format!("Illegal state: {} for this request. Try again later.", err.current_state),
                data: None,
            };
        }
        return ServerError {
            code: ErrorCode::InternalError,
            message: format!("Internal error: {:?}", internal_err),
            data: None,
        };
    }

    /// This function is used to make sure the km is up and running.
    /// it can be requested via the jsonRPC server using the following command:
    /// curl -sb -o /dev/null -X POST -d '{"jsonrpc": "2.0", "id": "1", "method": "getHealthCheck", "params": []}' -H "Content-Type: application/json" 127.0.0.1:3040
    pub fn health_check(epoch_provider: &EpochProvider) -> Value {
        // Ethereum
        let contract_signing_address = match epoch_provider.contract.get_signing_address() {
            Ok(addr) => addr,
            Err(_) => return Value::Bool(false),
        };
        // Enclave
        let enclave_signing_address: H160 = match esgx::equote::get_register_signing_address(*epoch_provider.eid) {
            Ok(addr) => addr.into(),
            Err(_) => return Value::Bool(false),
        };
        return Value::Bool(contract_signing_address == enclave_signing_address)
    }

    /// Endpoint for the get_state_keys and the health check method
    ///
    /// Example:
    /// curl -X POST --data '{"jsonrpc": "2.0", "id": "1", "method": "getStateKeys", "params": ["84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"]}' -H "Content-Type: application/json" http://127.0.0.1:3040/
    #[logfn(DEBUG)]
    pub fn start(&self) {
        let mut io = IoHandler::default();
        let epoch_provider = Arc::clone(&self.epoch_provider);
        let port = self.port;
        io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
            let request = params.parse::<StateKeyRequest>()?;
            let body = Self::get_state_keys(&epoch_provider, request).map_err(Self::handle_error)?; // Not sure that this is the best idiom
            Ok(body)
        });
        let hc_epoch_provider = Arc::clone(&self.epoch_provider);
        io.add_method(METHOD_GET_HEALTH_CHECK, move |_| {
            let body = Self::health_check(&hc_epoch_provider);
            Ok(body)
        });
        let server =
            ServerBuilder::new(io).start_http(&format!("0.0.0.0:{}", port).parse().unwrap()).expect("Unable to start RPC server");
        info!("JSON-RPC listening on port: {}", port);
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

    use enigma_types::{ContractAddress, Hash256};
    use epoch_u::epoch_types::ConfirmedEpochState;
    use esgx::epoch_keeper_u::set_or_verify_worker_params;
    use esgx::epoch_keeper_u::tests::get_worker_params;
    use esgx::general::init_enclave_wrapper;

    use super::*;

    // Data generated by an external client
    const REF_MSG: &str = "83a464617461a752657175657374a269649cccd763674174cc9b3f300dccd2ccb0cc8ba67075626b6579dc0040ccc90b2205ccf9cc9358661320ccffccb763ccb57614ccf8ccaa1fccb86d6a087869ccd81acce5ccf16fcc9206cc98344136cca4ccefccb105ccbbccca1c5057ccba25067eccc101cc82ccee21445cccf91e79ccb176447239";
    const REF_SIG: &str = "2535cfe1bcea215dc552acbca1a213354e055709f8e071c593bb9a8c1551b7791d6fd611ded1912065b3b518f6a75a1c78643b0a2e06397707b21768be637cb41b";
    const REF_RESPONSE: &str = "83a46461746181b1456e6372";
    const REF_WORKER: [u8; 20] = [161, 186, 144, 238, 40, 242, 102, 161, 178, 93, 177, 83, 107, 128, 189, 132, 112, 8, 163, 252];
    const REF_CONTRACT_ADDR: [u8; 32] = [253, 20, 84, 186, 169, 51, 74, 146, 65, 95, 59, 133, 9, 25, 170, 193, 33, 159, 199, 204, 122, 116, 189, 122, 37, 132, 117, 188, 103, 120, 103, 137];

    #[test]
    pub fn test_jsonrpc_get_state_keys() {
        let enclave = init_enclave_wrapper().unwrap();
        let workers: Vec<[u8; 20]> = vec![REF_WORKER];
        let stakes: Vec<u64> = vec![10000000000];
        let km_block_number = 1;
        let worker_params = get_worker_params(km_block_number, workers, stakes);
        let epoch_state = set_or_verify_worker_params(enclave.geteid(), &worker_params, None).unwrap();
        let rpc = {
            let mut io = IoHandler::new();
            let eid = enclave.geteid();
            io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
                let request = params.parse::<StateKeyRequest>().unwrap();
                println!("Calling get_enc_state_keys");
                let address = ContractAddress::from(REF_CONTRACT_ADDR);
                let response = get_enc_state_keys(eid, request, epoch_state.nonce, &[address]).unwrap();
                let response_data = serde_json::to_value(&response).unwrap();
                Ok(response_data)
            });
            test::Rpc::from(io)
        };
        for i in 0..5 {
            let response = rpc.request(METHOD_GET_STATE_KEYS, &(REF_MSG, REF_SIG, Value::Null, Value::Null));
            assert!(response.contains(REF_RESPONSE));
        }
        enclave.destroy();
    }

    #[test]
    pub fn test_find_epoch_contract_addresses() {
        let msg = REF_MSG.from_hex().unwrap();
        let request = StateKeyRequest { data: StringWrapper(msg.to_hex()), sig: StringWrapper(REF_SIG.to_string()), block_number: None, addresses: None };
        let address = Hash256::from(REF_CONTRACT_ADDR);
        let mut selected_workers: HashMap<Hash256, H160> = HashMap::new();
        selected_workers.insert(address, H160(REF_WORKER));
        let ether_block_number = U256::from(3);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, ether_block_number });
        let seed = U256::from(1);
        let sig = Bytes::from(REF_SIG.from_hex().unwrap());
        let nonce = U256::from(0);
        let km_block_number = U256::from(1);
        let epoch_state = EpochState { seed, sig, nonce, km_block_number, confirmed_state };
        let msg = PrincipalMessage::from_message(&request.get_data().unwrap()).unwrap();
        let results = PrincipalHttpServer::find_epoch_contract_addresses(&request, &msg, &epoch_state).unwrap();
        assert_eq!(results, vec![address])
    }
}
