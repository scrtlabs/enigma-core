use enigma_crypto::KeyPair;
use enigma_tools_m::{
    primitives::km_primitives::{PrincipalMessage, PrincipalMessageType},
    utils::EthereumAddress,
};
use enigma_types::ContractAddress;
use epoch_u::{epoch_provider::EpochProvider, epoch_types::EpochState};
use esgx::keys_keeper_u::get_enc_state_keys;
use failure::Error;
use jsonrpc_http_server::{
    jsonrpc_core::{Error as ServerError, ErrorCode, IoHandler, Params, Value},
    ServerBuilder,
};
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, sync::Arc};

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
            bail!("Cannot create a 65 bytes array from mismatching mismatching size slice.")
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

#[derive(Serialize, Debug, Clone)]
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

    fn find_epoch_contract_addresses(request: &StateKeyRequest, epoch_state: &EpochState) -> Result<Vec<ContractAddress>, Error> {
        let msg_slice = request.get_data()?;
        let sig = request.get_sig()?;
        let worker = KeyPair::recover(&msg_slice, sig)?.address();
        let addrs = epoch_state.get_contract_addresses(&worker.into())?;
        Ok(addrs)
    }

    #[logfn(DEBUG)]
    pub fn get_state_keys(epoch_provider: Arc<EpochProvider>, request: StateKeyRequest) -> Result<Value, Error> {
        println!("Got get_state_keys request: {:?}", request);
        let msg_slice = request.get_data()?;
        let msg = PrincipalMessage::from_message(&msg_slice)?;
        let response = match msg.data {
            PrincipalMessageType::Request(Some(addrs)) => {
                println!("Found addresses in message: {:?}", addrs);
                get_enc_state_keys(*epoch_provider.eid, request, None)?
            }
            PrincipalMessageType::Request(None) => {
                println!("No addresses in message, reading from epoch state...");
                let epoch_state = epoch_provider.get_state()?;
                let epoch_addrs = Self::find_epoch_contract_addresses(&request, &epoch_state)?;
                get_enc_state_keys(*epoch_provider.eid, request, Some(&epoch_addrs))?
            }
            _ => bail!("Invalid Principal message request"),
        };
        let response_data = serde_json::to_value(&response)?;
        Ok(response_data)
    }

    /// Endpoint for the get_state_keys method
    ///
    /// Example:
    /// curl -X POST --data '{"jsonrpc": "2.0", "method": "get_state_keys", "params": ["84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda", "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c"]' -H "Content-Type: application/json" http://127.0.0.1:3040/
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
    use web3::types::{H160, U256};
    use super::*;
    use enigma_types::ContractAddress;
    use epoch_u::epoch_types::ConfirmedEpochState;
    use rustc_hex::FromHex;
    use std::collections::HashMap;
    use web3::types::Bytes;
    use jsonrpc_test as test;
    use esgx::epoch_keeper_u::tests::get_worker_params;
    use esgx::epoch_keeper_u::set_worker_params;
    use serde_json::error::ErrorCode::EofWhileParsingObject;
    use epoch_u::epoch_provider::test::setup_epoch_storage;
    use esgx::general::init_enclave_wrapper;
    use std::thread;


    #[test]
    pub fn test_jsonrpc_get_state_keys() {
        setup_epoch_storage();
        let enclave = init_enclave_wrapper().unwrap();
        let rpc = {
            let mut io = IoHandler::new();
            let eid = enclave.geteid();
            io.add_method(METHOD_GET_STATE_KEYS, move |params: Params| {
                let request = params.parse::<StateKeyRequest>().unwrap();
                println!("The request: {:?}", request);
                let response = get_enc_state_keys(eid, request, None).unwrap();
                let response_data = serde_json::to_value(&response).unwrap();
                Ok(response_data)
            });
            test::Rpc::from(io)
        };
        let workers: Vec<[u8; 20]> = vec![[143, 123, 253, 113, 133, 173, 215, 156, 68, 228, 91, 227, 191, 31, 114, 35, 142, 245, 179, 32]];
        let stakes: Vec<u64> = vec![20000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        let epoch_state = set_worker_params(enclave.geteid(), &worker_params, None).unwrap();
        let ref_response_data = "83a46461746181b1456e63727970746564526573706f6e7365dc007eccf10c3a2037cccdccd71a453525ccea49cca7ccf151ccb115ccb400023364cc9d3accc72a21ccfcccd0cca8cc83cce4ccf1ccd8cc83ccc5ccdf28173d2062ccadcc885173ccef32cc96ccdf3a2c0562ccb27e2fccf951125ecc9e16cc860accf362cce3ccc107ccb42ccca7cc9036ccc0cca8cccccc84ccc473cc8629ccfb6665cc966d30ccb0cca9cca01970cce735cc98ccf07bccddccb6cc8701ccd2013ecca5000c4bcc8462cc9ccc8a08cc944f07ccff45ccf6cccd05ccfa6ba269649c000000000000000000000001a67075626b6579dc0040ccb3cc9a5dccddccb8cc8cccf1cc98cca2cca346cceacce14b26ccebccee3cccc60eccf9ccf5ccd24c5eccf7ccf0ccda367455ccffccfa78cc833b2a6b6944ccb7ccb31accd6cc8accac4acc83ccc9ccf61d265dccd82c43ccdb283cccf0cc9e4bcceacc82";
        let ref_response_sig = "a2c212a4590f6ad80c9998699382a407e9acac8af75c6b664f0b89812e85b9bc72fe9fbbe774cfc4af402d4f7002852c7527eed828aa84734a98ab0ceb9fd2b31b";
        for i in 0..100 {
            println!("Calling `getStateKeys` in thread {}", i);
            let msg = "84a67072656669789e456e69676d61204d657373616765a46461746181a75265717565737491dc0020ccfd1454ccbacca9334acc92415f3bcc850919ccaaccc121cc9fccc7cccc7a74ccbd7a25cc8475ccbc677867cc89a67075626b6579dc0040cce5195611cccb471ccc91cce77d30cc9c3b45cc9540ccbc627acc8eccc135ccf32bccaa1e63ccd914cc96ccaccc883a0c5c1b06ccb9cceecc8172cc93cca2cc8e0e631d22ccb7ccea5000525d76cc8b7dccc1cca213425bccdacca2a269649c000000000000000000000001";
            let sig = "2a4b0d392937300edd36beed4fb1300aed487d5529b6c2f843b7f6f4625644516a8263e27a142171b5ebd5895d3903693c85c681505128529154e302a80bb97c1c";
            let response = rpc.request(METHOD_GET_STATE_KEYS, &(msg, sig));
        }
        enclave.destroy();
    }

    #[test]
    pub fn test_find_epoch_contract_addresses() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sig = sign_message(&msg).unwrap();
        let request = StateKeyRequest { data: StringWrapper(msg.to_hex()), sig: StringWrapper(sig.to_hex()) };
        let address = ContractAddress::from([0u8; 32]);

        let mut selected_workers: HashMap<ContractAddress, H160> = HashMap::new();
        selected_workers.insert(address, H160(WORKER_SIGN_ADDRESS));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });
        let seed = U256::from(1);
        let sig = Bytes::from(sig.to_vec());
        let nonce = U256::from(0);
        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        let results = PrincipalHttpServer::find_epoch_contract_addresses(&request, &epoch_state).unwrap();
        println!("Found contract addresses: {:?}", results);
        assert_eq!(results, vec![address])
    }

    pub const WORKER_SIGN_ADDRESS: [u8; 20] =
        [95, 53, 26, 193, 96, 206, 55, 206, 15, 120, 191, 101, 13, 44, 28, 237, 80, 151, 54, 182];

    pub(crate) fn sign_message(msg: &Vec<u8>) -> Result<[u8; 65], Error> {
        let pkey = "79191a46ad1ed7a15e2bf64264c4b41fe6167ea887a5f7de82f52be073539730".from_hex()?;
        let mut pkey_slice: [u8; 32] = [0; 32];
        pkey_slice.copy_from_slice(&pkey);
        let key_pair = KeyPair::from_slice(&pkey_slice).unwrap();
        let sig = key_pair.sign(&msg).unwrap();
        Ok(sig)
    }
}
