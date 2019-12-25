use serde_json;
use serde_repr::{Serialize_repr, Deserialize_repr};
use zmq::Message;
use crate::db::{Delta, Stype, DeltaKey};
use hex::ToHex;
use failure::Error;

// These attributes enable the status to be casted as an i8 object as well
#[derive(Serialize_repr, Deserialize_repr, Clone, Debug)]
#[repr(i8)]
pub enum Status {
    Failed = -1,
    Passed = 0,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageRequest {
    pub id: String,
    #[serde(flatten)]
    pub request: IpcRequest
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageResponse {
    pub id: String,
    #[serde(flatten)]
    pub response: IpcResponse
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { #[serde(flatten)] result: IpcResults },
    GetTip { result: IpcDelta },
    GetTips { result: IpcResults },
    GetAllTips { result: IpcResults },
    GetAllAddrs { result: IpcResults },
    GetDelta { result: IpcResults },
    GetDeltas { result: IpcResults },
    GetContract { #[serde(flatten)] result: IpcResults },
    UpdateNewContract { address: String, result: IpcResults },
    UpdateNewContractOnDeployment { address: String, result: IpcResults },
    RemoveContract { address: String, result: IpcResults },
    UpdateDeltas { #[serde(flatten)] result: IpcResults },
    RemoveDeltas { #[serde(flatten)] result: IpcResults},
    NewTaskEncryptionKey { #[serde(flatten)] result: IpcResults },
    DeploySecretContract { #[serde(flatten)] result: IpcResults},
    ComputeTask { #[serde(flatten)] result: IpcResults },
    FailedTask { #[serde(flatten)] result: IpcResults },
    GetPTTRequest { #[serde(flatten)] result: IpcResults },
    PTTResponse { result: IpcResults },
    Error { msg: String },
}

impl IpcResponse {
    pub fn display_without_bytecode(&self) -> String {
        match self {
            IpcResponse::DeploySecretContract {result: e} => {
                match e {
                    IpcResults::DeployResult {  used_gas,
                                                delta,
                                                ethereum_address,
                                                ethereum_payload,
                                                signature, .. } =>
                        format!("IpcResponse {{ used_gas: {}, delta: {:?}, ethereum_address: {}, ethereum_payload: {}, signature: {} }}",
                        used_gas, delta, ethereum_address, ethereum_payload, signature),
                    _ => "".to_string(),
                }
            },
            _ => "".to_string(),
        }
    }

    pub fn display_bytecode(&self) -> String {
        match self {
            IpcResponse::DeploySecretContract {result: e} => {
                match e {
                    IpcResults::DeployResult {  output,.. } =>
                        format!("{}", output),
                    _ => "".to_string(),
                }
            },
            _ => "".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum IpcResults {
    Errors(Vec<IpcStatusResult>),
    #[serde(rename = "result")]
    Request { request: String, #[serde(rename = "workerSig")] sig: String },
    Addresses(Vec<String>),
    Delta(String),
    Deltas(Vec<IpcDelta>),
    #[serde(rename = "result")]
    GetContract {
        address: String,
        bytecode: Vec<u8>,
    },
    Status(Status),
    Tips(Vec<IpcDelta>),
    #[serde(rename = "result")]
    DeltasResult { status: Status, errors: Vec<IpcStatusResult> },
    #[serde(rename = "result")]
    DHKey { #[serde(rename = "workerEncryptionKey")] dh_key: String, #[serde(rename = "workerSig")] sig: String },
    #[serde(rename = "result")]
    RegistrationParams { #[serde(rename = "signingKey")] signing_key: String, report: String, signature: String },
    #[serde(rename = "result")]
    ComputeResult {
        #[serde(rename = "usedGas")]
        used_gas: u64,
        output: String,
        delta: IpcDelta,
        #[serde(rename = "ethereumAddress")]
        ethereum_address: String,
        #[serde(rename = "ethereumPayload")]
        ethereum_payload: String,
        signature: String,
    },
    #[serde(rename = "result")]
    DeployResult {
        #[serde(rename = "preCodeHash")]
        pre_code_hash: String,
        #[serde(rename = "usedGas")]
        used_gas: u64,
        output: String,
        delta: IpcDelta,
        #[serde(rename = "ethereumAddress")]
        ethereum_address: String,
        #[serde(rename = "ethereumPayload")]
        ethereum_payload: String,
        signature: String,
    },
    #[serde(rename = "result")]
    FailedTask {
        output: String,
        #[serde(rename = "usedGas")]
        used_gas: u64,
        signature: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetRegistrationParams,
    GetTip { input: String },
    GetTips { input: Vec<String> },
    GetAllTips,
    GetAllAddrs,
    GetDelta { input: IpcDelta },
    GetDeltas { input: Vec<IpcDeltasRange> },
    GetContract { input: String },
    UpdateNewContract { address: String, bytecode: Vec<u8> },
    UpdateNewContractOnDeployment {address: String, bytecode: String, delta: IpcDelta},
    RemoveContract { address: String },
    UpdateDeltas { deltas: Vec<IpcDelta> },
    RemoveDeltas { input: Vec<IpcDeltasRange> },
    NewTaskEncryptionKey { #[serde(rename = "userPubKey")] user_pubkey: String },
    DeploySecretContract { input: IpcTask},
    ComputeTask { input: IpcTask },
    GetPTTRequest,
    PTTResponse {  input: PrincipalResponse },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcTask {
    #[serde(rename = "preCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_code: Option<Vec<u8>>,
    #[serde(rename = "encryptedArgs")]
    pub encrypted_args: String,
    #[serde(rename = "encryptedFn")]
    pub encrypted_fn: String,
    #[serde(rename = "userDHKey")]
    pub user_dhkey: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "contractAddress")]
    pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcStatusResult {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
    pub status: Status,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct IpcDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "address")]
    pub contract_address: Option<String>,
    pub key: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcDeltasRange {
    pub address: String,
    pub from: u32,
    pub to: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalResponse {
    pub response: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Addresses {
    pub addresses: Vec<String>,
}

impl std::ops::Deref for Addresses {
    type Target = Vec<String>;
    fn deref(&self) -> &Vec<String> {
        &self.addresses
    }
}

impl IpcMessageResponse {
    pub fn from_response(response: IpcResponse, id: String) -> Self {
        Self { id, response }
    }
}
impl IpcMessageRequest {
    pub fn from_request(request: IpcRequest, id: String) -> Self {
        Self { id, request }
    }
}



impl IpcDelta {
    pub fn from_delta_key(k: DeltaKey, v: &[u8]) -> Result<Self, Error> {
        if let Stype::Delta(indx) = k.key_type {
            Ok( IpcDelta { contract_address: Some(k.contract_address.to_hex()), key: indx, data: Some(v.to_vec()) } )
        } else {
            bail!("This isn't a delta")
        }
    }
}

impl From<Delta> for IpcDelta {
    fn from(delta: Delta) -> Self {
        let data = if delta.value.len() == 0 { None } else { Some ( delta.value ) };
        let key = delta.key.key_type.unwrap_delta();

        IpcDelta { contract_address: None, key, data }
    }
}

impl From<Message> for IpcMessageRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        let req: Self = serde_json::from_str(msg_str).expect(msg_str);
        req
    }
}

impl Into<Message> for IpcMessageResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from(&msg)
    }
}

pub(crate) trait UnwrapError<T> {
    fn unwrap_or_error(self) -> T;
}

impl<E: std::fmt::Display> UnwrapError<IpcResponse> for Result<IpcResponse, E> {
    fn unwrap_or_error(self) -> IpcResponse {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped p2p Message failed: {}", e);
                IpcResponse::Error {msg: format!("{}", e)}
            }
        }
    }
}
