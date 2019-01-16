use serde_json;
use zmq::Message;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { id: String, result: IpcRegistrationParams },
    IdentityChallenge { id: String, nonce: String, signature: IpcIdentityChallenge },
    GetTip { id: String, result: IpcDelta },
    GetTips { id: String, result: IpcResults },
    GetAllTips { id: String, result: Vec<IpcDelta> },
    GetAllAddrs { id: String, result: IpcResults },
    GetDelta { id: String, result: IpcResults },
    GetDeltas { id: String, result: IpcResults },
    GetContract { id: String, result: IpcResults },
    UpdateNewContract { id: String, address: String, result: IpcResults },
    UpdateDeltas { id: String, result: IpcUpdateDeltasResult },
    NewTaskEncryptionKey { id: String, result: IpcDHMessage },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase", rename = "result")]
pub enum IpcResults {
    Addresses(Vec<String>),
    Delta(String),
    Deltas(Vec<IpcDelta>),
    Bytecode(String),
    Status(String),
    Tips(Vec<IpcDelta>),
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcDHMessage {
    #[serde(rename = "workerEncryptionKey")]
    pub dh_key: String,
    #[serde(rename = "workerSig")]
    pub sig: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcRegistrationParams {
    #[serde(rename = "signingKey")]
    pub sigining_key: String,
    pub quote: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcIdentityChallenge {
    pub nonce: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcUpdateDeltasResult {
    pub status: u8,
    pub errors: Vec<IpcDeltaResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcDeltaResult {
    pub address: String,
    pub key: u32,
    pub status: u8,
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

impl From<Message> for IpcRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        serde_json::from_str(msg_str).expect(msg_str)
    }
}

impl Into<Message> for IpcResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from_slice(&msg)
    }
}

pub(crate) trait UnwrapDefault<T> {
    fn unwrap_or_default(self) -> T;
}

impl<E: std::fmt::Debug> UnwrapDefault<Message> for Result<Message, E> {
    fn unwrap_or_default(self) -> Message {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped p2p Message failed: {:?}", e);
                Message::new()
            }
        }
    }
}
