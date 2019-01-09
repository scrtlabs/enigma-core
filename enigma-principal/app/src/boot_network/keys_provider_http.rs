use std::string::ToString;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use failure::Error;
use jsonrpc_minihttp_server::cors::AccessControlAllowOrigin;
use jsonrpc_minihttp_server::DomainsValidation;
use jsonrpc_minihttp_server::jsonrpc_core::{Error as ServerError, ErrorCode, IoHandler, Params, Value};
use jsonrpc_minihttp_server::ServerBuilder;
use rustc_hex::FromHex;
use rustc_hex::ToHex;

use esgx::keys_keeper_u::get_enc_state_keys;

const METHOD_GET_STATE_KEYS: &str = "get_state_keys";

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
    pub request_message: StringWrapper,
    pub worker_sig: StringWrapper,
}

#[derive(Serialize, Debug, Clone)]
pub struct StateKeyResponse {
    pub encrypted_response_message: StringWrapper,
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

pub struct PrincipalHttpServer {
    eid: Arc<AtomicU64>,
    pub port: String,
}

impl PrincipalHttpServer {
    pub fn new(eid: Arc<AtomicU64>, port: &str) -> PrincipalHttpServer {
        PrincipalHttpServer { eid, port: port.to_string() }
    }

    fn get_state_keys_internal(request: StateKeyRequest, eid: &Arc<AtomicU64>) -> Result<String, Error> {
        println!("Got get_state_keys request: {:?}", request);
        let response = get_enc_state_keys(eid.load(Ordering::SeqCst), request)?;
        let response_data = serde_json::to_string_pretty(&response)?;
        Ok(response_data)
    }

    /// Endpoint for the get_state_keys method
    ///
    /// Example:
    /// curl -X POST --data '{"jsonrpc": "2.0", "method": "get_state_keys", "params": ["84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"], "id": 1}' -H "Content-Type: application/json" http://127.0.0.1:3040/
    ///
    pub fn start(&self) {
        let mut io = IoHandler::default();
        let eid = Arc::clone(&self.eid);
        io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
            let request = params.parse::<StateKeyRequest>()?;
            let body = match PrincipalHttpServer::get_state_keys_internal(request, &eid) {
                Ok(body) => body,
                Err(err) => return Err(ServerError { code: ErrorCode::InternalError, message: format!("Unable to get keys: {:?}", err), data: None }),
            };
            Ok(Value::String(body))
        });

        let server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Null]))
            .start_http(&format!("127.0.0.1:{}", self.port).parse().unwrap())
            .expect("Unable to start RPC server");

        server.wait().unwrap();
        println!("JSON-RPC HTTP server listening on port: {}", self.port);
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    #[test]
    pub fn request_state_key() {
        println!("requesting the state key from the Principal");
    }
}
