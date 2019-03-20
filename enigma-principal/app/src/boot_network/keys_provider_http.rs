use std::convert::TryInto;
use std::string::ToString;
use std::sync::Arc;

use ethereum_types::H256;
use failure::Error;
use jsonrpc_http_server::cors::AccessControlAllowOrigin;
use jsonrpc_http_server::DomainsValidation;
use jsonrpc_http_server::jsonrpc_core::{Error as ServerError, ErrorCode, IoHandler, Params, Value};
use jsonrpc_http_server::ServerBuilder;
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use sgx_types::sgx_enclave_id_t;

use epoch_u::epoch_provider::EpochProvider;
use epoch_u::epoch_types::EpochState;
use esgx::keys_keeper_u::get_enc_state_keys;
use keys_u::km_reader::PrincipalMessageReader;

const METHOD_GET_STATE_KEYS: &str = "getStateKeys";


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StringWrapper(pub String);

impl TryInto<Vec<u8>> for StringWrapper {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let value = &self;
        Ok(value.0.from_hex()?)
    }
}

impl TryInto<[u8; 65]> for StringWrapper {
    type Error = Error;

    fn try_into(self) -> Result<[u8; 65], Self::Error> {
        let value = &self;
        let bytes = value.0.from_hex()?;
        if bytes.len() != 65 {
            bail!("Cannot create a 65 bytes array from mismatching mismatching size slice.")
        }
        let mut slice: [u8; 65] = [0; 65];
        slice.copy_from_slice(&bytes[..]);
        Ok(slice)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct StateKeyRequest {
    pub data: StringWrapper,
    pub sig: StringWrapper,
}

#[derive(Serialize, Debug, Clone)]
pub struct StateKeyResponse {
    pub data: StringWrapper,
    pub sig: StringWrapper,
}

impl<H: ToHex> From<H> for StringWrapper {
    fn from(bytes: H) -> Self {
        StringWrapper(bytes.to_hex())
    }
}

pub struct PrincipalHttpServer {
    epoch_provider: Arc<EpochProvider>,
    pub port: String,
}

impl PrincipalHttpServer {
    pub fn new(epoch_provider: Arc<EpochProvider>, port: &str) -> PrincipalHttpServer {
        PrincipalHttpServer { epoch_provider, port: port.to_string() }
    }

    fn find_epoch_contract_addresses(reader: PrincipalMessageReader, sig: [u8; 65], epoch_state: EpochState) -> Result<Vec<H256>, Error> {
        let worker = reader.get_signing_address(sig)?;
        let addrs = epoch_state.get_contract_addresses(&worker)?;
        Ok(addrs)
    }

    #[logfn(DEBUG)]
    pub fn get_state_keys(epoch_provider: Arc<EpochProvider>, request: StateKeyRequest) -> Result<Value, Error> {
        println!("Got get_state_keys request: {:?}", request);
        let reader = PrincipalMessageReader::new(request.data.clone().try_into()?)?;
        let addrs = reader.get_contract_addresses()?;
        let eid = epoch_provider.eid.clone();
        let response = match addrs {
            Some(addrs) => {
                println!("Found addresses in message: {:?}", addrs);
                get_enc_state_keys(*eid, request, None)?
            }
            None => {
                println!("No addresses in message, reading from epoch state...");
                let epoch_state = epoch_provider.get_state()?;
                let epoch_addrs = Self::find_epoch_contract_addresses(reader, request.sig.clone().try_into()?, epoch_state)?;
                get_enc_state_keys(*eid, request, Some(epoch_addrs))?
            }
        };
        let response_data = serde_json::to_value(&response)?;
        Ok(response_data)
    }

    /// Endpoint for the get_state_keys method
    ///
    /// Example:
    /// curl -X POST --data '{"jsonrpc": "2.0", "method": "get_state_keys", "params": ["84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"]' -H "Content-Type: application/json" http://127.0.0.1:3040/
    ///
    pub fn start(&self) {
        let mut io = IoHandler::default();
        let epoch_provider = Arc::clone(&self.epoch_provider);
        io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
            let epoch_provider = epoch_provider.clone();
            let request = params.parse::<StateKeyRequest>()?;
            let body = match Self::get_state_keys(epoch_provider, request) {
                Ok(body) => body,
                Err(err) => return Err(ServerError { code: ErrorCode::InternalError, message: format!("Unable to get keys: {:?}", err), data: None }),
            };
            Ok(body)
        });
        let server = ServerBuilder::new(io)
            .start_http(&format!("0.0.0.0:{}", self.port).parse().unwrap())
            .expect("Unable to start RPC server");
        println!("JSON-RPC HTTP server listening on port: {}", self.port);
        server.wait();
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ethereum_types::{H160, U256};
    use rustc_hex::FromHex;
    use web3::types::Bytes;

    use epoch_u::epoch_types::ConfirmedEpochState;
    use keys_u::km_reader::test::{sign_message, WORKER_SIGN_ADDRESS};

    use super::*;

    #[test]
    pub fn test_find_epoch_contract_addresses() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sig = sign_message(&msg).unwrap();
        let request = StateKeyRequest { data: StringWrapper(msg.to_hex()), sig: StringWrapper(sig.to_vec().to_hex()) };
        let reader = PrincipalMessageReader::new(request.data.clone().try_into().unwrap()).unwrap();
        let mut selected_workers: HashMap<H256, H160> = HashMap::new();
        selected_workers.insert(H256([0; 32]), H160(WORKER_SIGN_ADDRESS));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });
        let seed = U256::from(1);
        let sig = Bytes::from(sig.to_vec());
        let nonce = U256::from(0);
        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        let results = PrincipalHttpServer::find_epoch_contract_addresses(reader, request.sig.try_into().unwrap(), epoch_state).unwrap();
        println!("Found contract addresses: {:?}", results);
        assert_eq!(results, vec![H256([0; 32])])
    }

    #[test]
    pub fn test_get_state_keys() {

    }
}
