use zmq::Message;
use serde_json;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { id: String, #[serde(rename = "signingKey")] sigining_key: String,  quote: String},
    IdentityChallenge { id: String, nonce: String, signature: String, },
    GetTip { id: String , result: IpcDelta, },
    GetTips {id: String, result: Vec<IpcDelta> },
    GetAllTips { id: String, result: Vec<IpcDelta> },
    GetAllAddrs { id: String, result: IpcResults },
    GetDelta { id: String, result: IpcResults },
    GetDeltas { id: String, result: IpcResults },
    GetContract { id: String, result: IpcResults },
    UpdateNewContract { id: String, address: String, result: IpcResults },
    UpdateDeltas { id: String, general_status: String, result: IpcResults },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(rename = "result")]
pub enum IpcResults {
    Addresses(Vec<String>),
    Delta(String),
    Deltas(Vec<IpcDelta>),
    Bytecode(String),
    Status(String)
}



#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetRegistrationParams { id: String },
    IdentityChallenge { id: String, nonce: String },
    GetTip { id: String, input: String },
    GetTips {id: String, input: Vec<String> },
    GetAllTips { id: String },
    GetAllAddrs { id: String },
    GetDelta { id: String, input: IpcDelta },
    GetDeltas { id: String, input: Vec<IpcGetDeltas> },
    GetContract { id: String, input: String },
    UpdateNewContract { id: String, address: String, bytecode: String },
    UpdateDeltas { id: String, deltas: Vec<IpcDelta> },

}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcDelta {
    pub address: Option<String>,
    pub key: u32,
    pub delta: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcGetDeltas {
    pub address: String,
    pub from: u32,
    pub to: u32
}


impl From<Message> for IpcRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        serde_json::from_str(msg_str).unwrap()
    }
}

impl Into<Message> for IpcResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from_slice(&msg).unwrap()
    }
}