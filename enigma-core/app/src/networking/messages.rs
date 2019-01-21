use serde_json;
use zmq::Message;
use crate::db::{Delta, Stype, DeltaKey};
use hex::ToHex;
use failure::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { id: String, #[serde(flatten)] result: IpcResults },
    IdentityChallenge { id: String, nonce: String, signature: IpcIdentityChallenge },
    GetTip { id: String, result: IpcDelta },
    GetTips { id: String, result: IpcResults },
    GetAllTips { id: String, result: IpcResults },
    GetAllAddrs { id: String, result: IpcResults },
    GetDelta { id: String, result: IpcResults },
    GetDeltas { id: String, result: IpcResults },
    GetContract { id: String, result: IpcResults },
    UpdateNewContract { id: String, address: String, #[serde(flatten)] result: IpcResults },
    UpdateDeltas { id: String, #[serde(flatten)] result: IpcResults },
    NewTaskEncryptionKey { id: String, #[serde(flatten)] result: IpcResults },
    DeploySecretContract { id: String, #[serde(flatten)] result: IpcResults},
    ComputeTask { id: String, #[serde(flatten)] result: IpcResults },
    GetPTTRequest { id: String, #[serde(flatten)] result: IpcResults },
    PTTResponse { id: String, result: Vec<IpcStatusResult> },
    Error { id: String, error: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum IpcResults {
    Request { request: String, #[serde(rename = "workerSig")] sig: String },
    Addresses(Vec<String>),
    Delta(String),
    Deltas(Vec<IpcDelta>),
    Bytecode(String),
    Status(i8),
    Tips(Vec<IpcDelta>),
    #[serde(rename = "result")]
    UpdateDeltasResult { status: i8, errors: Vec<IpcStatusResult> },
    #[serde(rename = "result")]
    DHKey { #[serde(rename = "workerEncryptionKey")] dh_key: String, #[serde(rename = "workerSig")] sig: String },
    #[serde(rename = "result")]
    RegistrationParams { #[serde(rename = "signingKey")] sigining_key: String, report: String, signature: String },
    #[serde(rename = "result")]
    TaskResult {
        #[serde(rename = "exeCode")]
        exe_code: Option<String>,
        #[serde(rename = "preCodeHash")]
        pre_code_hash: Option<String>,
        #[serde(rename = "usedGas")]
        used_gas: u64,
        output: Option<String>,
        delta: IpcDelta,
        signature: String,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetRegistrationParams { id: String },
    IdentityChallenge { id: String, nonce: String },
    GetTip { id: String, input: String },
    GetTips { id: String, input: Vec<String> },
    GetAllTips { id: String },
    GetAllAddrs { id: String },
    GetDelta { id: String, input: IpcDelta },
    GetDeltas { id: String, input: Vec<IpcGetDeltas> },
    GetContract { id: String, input: String },
    UpdateNewContract { id: String, address: String, bytecode: String },
    UpdateDeltas { id: String, deltas: Vec<IpcDelta> },
    NewTaskEncryptionKey { id: String, #[serde(rename = "userPubKey")] user_pubkey: String },
    DeploySecretContract { id: String, input: IpcTask},
    ComputeTask { id: String, input: IpcTask },
    GetPTTRequest { id: String, addresses: Vec<String> },
    PTTResponse { id: String,  response: String },
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
    #[serde(rename = "GasLimit")]
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
    pub status: i8,
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

impl IpcDelta {
    pub fn from_delta_key(k: DeltaKey, v: Vec<u8>) -> Result<Self, Error> {
        if let Stype::Delta(indx) = k.key_type {
            Ok( IpcDelta { address: Some(k.hash.to_hex()), key: indx, delta: Some(v.to_hex()) } )
        } else {
            bail!("This isn't a delta")
        }
    }
}


impl IpcRequest {
    pub fn unwrap_id(self) -> String {
        match self {
            IpcRequest::GetRegistrationParams { id, .. } => id,
            IpcRequest::IdentityChallenge { id, .. } => id,
            IpcRequest::GetTip { id, .. } => id,
            IpcRequest::GetTips { id, .. } => id,
            IpcRequest::GetAllTips { id } => id,
            IpcRequest::GetAllAddrs { id } => id,
            IpcRequest::GetDelta { id, .. } => id,
            IpcRequest::GetDeltas { id, .. } => id,
            IpcRequest::GetContract { id, .. } => id,
            IpcRequest::UpdateNewContract { id, .. } => id,
            IpcRequest::UpdateDeltas { id, .. } => id,
            IpcRequest::NewTaskEncryptionKey { id, .. } => id,
            IpcRequest::DeploySecretContract { id, ..} => id,
            IpcRequest::ComputeTask { id, .. } => id,
            IpcRequest::GetPTTRequest { id, .. } => id,
            IpcRequest::PTTResponse { id, .. } => id,
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

impl From<Message> for IpcRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        println!("got: {:?}", msg_str);
        let req: IpcRequest = serde_json::from_str(msg_str).expect(msg_str);
        req
    }
}

impl Into<Message> for IpcResponse {
    fn into(self) -> Message {
        println!("respond: {:?}", serde_json::to_string(&self).unwrap());
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from_slice(&msg)
    }
}

pub(crate) trait UnwrapError<T, D> {
    fn unwrap_or_error(self, _: D) -> T;
}

impl<E: std::fmt::Debug> UnwrapError<Message, String> for Result<Message, E> {
    fn unwrap_or_error(self, id: String) -> Message {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped p2p Message failed: {:?}", e);
                IpcResponse::Error { id, error: format!("{:?}", e) }.into()
            }
        }
    }
}
