use serde_json;
use zmq::Message;
use crate::db::{Delta, Stype, DeltaKey};
use hex::ToHex;
use failure::Error;

type Status = i8;
pub const FAILED: Status = -1;

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
    IdentityChallenge { nonce: String, signature: IpcIdentityChallenge },
    GetTip { result: IpcDelta },
    GetTips { result: IpcResults },
    GetAllTips { result: IpcResults },
    GetAllAddrs { result: IpcResults },
    GetDelta { result: IpcResults },
    GetDeltas { result: IpcResults },
    GetContract { result: IpcResults },
    UpdateNewContract { address: String, #[serde(flatten)] result: IpcResults },
    UpdateDeltas { #[serde(flatten)] result: IpcResults },
    NewTaskEncryptionKey { #[serde(flatten)] result: IpcResults },
    DeploySecretContract { #[serde(flatten)] result: IpcResults},
    ComputeTask { #[serde(flatten)] result: IpcResults },
    GetPTTRequest { #[serde(flatten)] result: IpcResults },
    PTTResponse { result: Vec<IpcStatusResult> },
    Error { error: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum IpcResults {
    #[serde(rename = "result")]
    Request { request: String, #[serde(rename = "workerSig")] sig: String },
    Addresses(Vec<String>),
    Delta(String),
    Deltas(Vec<IpcDelta>),
    Bytecode(String),
    Status(Status),
    Tips(Vec<IpcDelta>),
    #[serde(rename = "result")]
    UpdateDeltasResult { status: Status, errors: Vec<IpcStatusResult> },
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
        signature: String,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetRegistrationParams,
    IdentityChallenge { nonce: String },
    GetTip { input: String },
    GetTips { input: Vec<String> },
    GetAllTips,
    GetAllAddrs,
    GetDelta { input: IpcDelta },
    GetDeltas { input: Vec<IpcGetDeltas> },
    GetContract { input: String },
    UpdateNewContract { address: String, bytecode: String },
    UpdateDeltas { deltas: Vec<IpcDelta> },
    NewTaskEncryptionKey { #[serde(rename = "userPubKey")] user_pubkey: String },
    DeploySecretContract { input: IpcTask},
    ComputeTask { input: IpcTask },
    GetPTTRequest { addresses: Vec<String> },
    PTTResponse {  response: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcTask {
    #[serde(rename = "preCode")]
    pub pre_code: Option<String>,
    #[serde(rename = "encryptedArgs")]
    pub encrypted_args: String,
    #[serde(rename = "encryptedFn")]
    pub encrypted_fn: String,
    #[serde(rename = "userPubKey")]
    pub user_pubkey: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "contractAddress")]
    pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcIdentityChallenge {
    pub nonce: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcStatusResult {
    pub address: String,
    pub key: Option<u32>,
    pub status: Status,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct IpcDelta {
    pub address: Option<String>,
    pub key: u32,
    pub delta: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcGetDeltas {
    pub address: String,
    pub from: u32,
    pub to: u32,
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
    pub fn from_delta_key(k: DeltaKey, v: Vec<u8>) -> Result<Self, Error> {
        if let Stype::Delta(indx) = k.key_type {
            Ok( IpcDelta { address: Some(k.hash.to_hex()), key: indx, delta: Some(v.to_hex()) } )
        } else {
            bail!("This isn't a delta")
        }
    }
}

impl From<Delta> for IpcDelta {
    fn from(delta: Delta) -> Self {
        let address = delta.key.hash.to_hex();
        let value = delta.value.to_hex();
        let key = delta.key.key_type.unwrap_delta();

        IpcDelta { address: Some(address), key, delta: Some(value) }
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
        Message::from_slice(&msg)
    }
}

pub(crate) trait UnwrapError<T, D> {
    fn unwrap_or_error(self, _: D) -> T;
}

impl<E: std::fmt::Debug> UnwrapError<IpcResponse, String> for Result<IpcResponse, E> {
    fn unwrap_or_error(self, id: String) -> IpcResponse {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped p2p Message failed: {:?}", e);
                IpcResponse::Error {error: format!("{:?}", e)}
            }
        }
    }
}
