use serde_json;
use zmq::Message;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { id: String, result: IpcResults },
    IdentityChallenge { id: String, nonce: String, signature: IpcIdentityChallenge },
    GetTip { id: String, result: IpcDelta },
    GetTips { id: String, result: IpcResults },
    GetAllTips { id: String, result: IpcResults },
    GetAllAddrs { id: String, result: IpcResults },
    GetDelta { id: String, result: IpcResults },
    GetDeltas { id: String, result: IpcResults },
    GetContract { id: String, result: IpcResults },
    UpdateNewContract { id: String, address: String, result: IpcResults },
    UpdateDeltas { id: String, result: IpcResults },
    NewTaskEncryptionKey { id: String, result: IpcResults },
    DeploySecretContract { id: String, result: IpcResults},
    ComputeTask { id: String, result: IpcResults },
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
    UpdateDeltasResult { status: u8, errors: Vec<IpcDeltaResult> },
    DHKey { #[serde(rename = "workerEncryptionKey")] dh_key: String, #[serde(rename = "workerSig")] sig: String },
    RegistrationParams { #[serde(rename = "signingKey")] sigining_key: String, report: String, signature: String },
    TaskResult {
        #[serde(rename = "exeCode")]
        exe_code: Option<String>,
        #[serde(rename = "preCodeHash")]
        pre_code_hash: Option<String>,
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
        let req: IpcRequest = serde_json::from_str(msg_str).expect(msg_str);
        println!("got: {:?}", req);
        req
    }
}

impl Into<Message> for IpcResponse {
    fn into(self) -> Message {
        println!("respond: {:?}", self);
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
