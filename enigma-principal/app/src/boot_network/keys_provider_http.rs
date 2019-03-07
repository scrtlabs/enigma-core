use std::string::ToString;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use failure::Error;
use jsonrpc_http_server::cors::AccessControlAllowOrigin;
use jsonrpc_http_server::DomainsValidation;
use jsonrpc_http_server::jsonrpc_core::{Error as ServerError, ErrorCode, IoHandler, Params, Value};
use jsonrpc_http_server::ServerBuilder;
use rmp_serde::{Deserializer, Serializer};
use rustc_hex::FromHex;
use rustc_hex::ToHex;
use serde::{Deserialize, Serialize};
use sgx_types::sgx_enclave_id_t;

use boot_network::epoch_provider::EpochProvider;
use enigma_types::{ContractAddress, StateKey};
use esgx::keys_keeper_u::get_enc_state_keys;

const METHOD_GET_STATE_KEYS: &str = "getStateKeys";

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum PrincipalMessageType {
    Request(Option<Vec<ContractAddress>>),
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PrincipalMessage {
    prefix: [u8; 14],
    pub data: PrincipalMessageType,
    pubkey: Vec<u8>,
    id: [u8; 12],
}

pub struct PrincipalMessageTranslator {
    pub request: Vec<u8>,
    principal_message: PrincipalMessage,
}

impl PrincipalMessageTranslator {
    pub fn new(request: Vec<u8>) -> Result<Self, Error> {
        let principal_message = PrincipalMessageTranslator::deserialize(&request)?;
        Ok(PrincipalMessageTranslator { request, principal_message })
    }

    pub fn deserialize(msg: &[u8]) -> Result<PrincipalMessage, Error> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)?;
        println!("The deserialized message: {:?}", res);
        let msg: PrincipalMessage = serde_json::from_value(res).unwrap();
        Ok(msg)
    }

    pub fn get_data(&self) -> Result<Option<Vec<ContractAddress>>, Error> {
        let data = match self.principal_message.data.clone() {
            PrincipalMessageType::Request(data) => data,
            _ => bail!("Invalid Principal message request"),
        };
        Ok(data)
    }

    pub fn insert_contract_addresses(&self, addrs: Vec<ContractAddress>) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let mut principal_message = self.principal_message.clone();
        let val = match serde_json::to_value(principal_message) {
            Ok(val) => val,
            Err(err) => bail!("Cannot serialize modified Principal message: {:?}", err),
        };
        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StringWrapper(pub String);

impl Into<Vec<u8>> for StringWrapper {
    fn into(self) -> Vec<u8> {
        let value = &self;
        value.0.from_hex().unwrap()
    }
}

impl Into<[u8; 65]> for StringWrapper {
    fn into(self) -> [u8; 65] {
        let value = &self;
        let bytes = value.0.from_hex().unwrap();
        let mut slice: [u8; 65] = [0; 65];
        slice.copy_from_slice(&bytes[..]);
        slice
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

impl From<Vec<u8>> for StringWrapper {
    fn from(bytes: Vec<u8>) -> Self {
        StringWrapper(bytes.to_hex())
    }
}

impl From<[u8; 65]> for StringWrapper {
    fn from(bytes: [u8; 65]) -> Self {
        StringWrapper(bytes.to_vec().to_hex())
    }
}

impl From<[u8; 64]> for StringWrapper {
    fn from(bytes: [u8; 64]) -> Self {
        StringWrapper(bytes.to_vec().to_hex())
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

    fn get_state_keys_internal(request: StateKeyRequest, eid: sgx_enclave_id_t) -> Result<Value, Error> {
        println!("Got get_state_keys request: {:?}", request);
        let response = get_enc_state_keys(eid, request)?;
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
        let child_eid = Arc::clone(&self.epoch_provider.eid);
        io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
            let request = params.parse::<StateKeyRequest>()?;
            let eid = child_eid.load(Ordering::SeqCst);
            let body = match PrincipalHttpServer::get_state_keys_internal(request, eid) {
                Ok(body) => body,
                Err(err) => return Err(ServerError { code: ErrorCode::InternalError, message: format!("Unable to get keys: {:?}", err), data: None }),
            };
            Ok(body)
        });
        let server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Null]))
            .start_http(&format!("0.0.0.0:{}", self.port).parse().unwrap())
            .expect("Unable to start RPC server");
        println!("JSON-RPC HTTP server listening on port: {}", self.port);
        server.wait();
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use rustc_hex::FromHex;
    use boot_network::keys_provider_http::{PrincipalHttpServer, PrincipalMessageTranslator};
    use enigma_types::ContractAddress;

    #[test]
    pub fn test_decode_message() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let processor = PrincipalMessageTranslator::new(msg).unwrap();
        let data = processor.get_data().unwrap();
        println!("The decoded Principal request: {:?}", data);
    }

    #[test]
    pub fn test_insert_secret_contract_addresses() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let processor = PrincipalMessageTranslator::new(msg).unwrap();
        let addrs: Vec<ContractAddress> = vec![[0u8; 32].into(), [1u8; 32].into(), [2u8; 32].into()];
        let out_msg = processor.insert_contract_addresses(addrs).unwrap();
        println!("The Principal message request with addresses: {:?}", out_msg);
    }
}
