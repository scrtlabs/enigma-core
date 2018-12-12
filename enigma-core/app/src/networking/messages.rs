//use zmq;
//use futures::{Future, Stream};
//use tokio_zmq::{prelude::*, Rep, Multipart};
//use std::sync::Arc;
//
//fn main() {
//    let ctx = Arc::new(zmq::Context::new());
//    let rep_fut = Rep::builder(ctx).bind("tcp://*:6111").build();
//
//    let runner = rep_fut.and_then(|rep| {
//        let (sink, stream) = rep.sink_stream(25).split();
//
//        stream.map(handle_message).forward(sink)
//    });
//
//    let b = runner.wait();
//}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetRegistrationParams { id: String, #[serde(rename = "signingKey")] sigining_key: String,  quote: String},
    IdentityChallenge { id: String, nonce: String, signature: String, },
    GetTip { id: String, input: String , result: IpcDelta, },
    GetTips {id: String, result: Vec<IpcDelta> },
    GetAllTips { id: String, result: Vec<IpcDelta> },
    GetAllAddrs { id: String, result: IpcResults },
    GetDelta { id: String, result: IpcResults },
    GetDeltas { id: String, result: IpcResults },
    GetContract { id: String, result: IpcResults },
    UpdateNewContract { id: String, address: String, status: String },
    UpdateDeltas { id: String, general_status: String, result: IpcResults },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(rename = "result")]
pub enum IpcResults {
    Addresses(Vec<String>),
    Delta(String),
    Deltas { address: String, key: u32, data: String },
    Bytecode(String),
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
    address: Option<String>,
    key: u32,
    delta: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcGetDeltas {
    pub address: String,
    pub from: u32,
    pub to: u32
}





fn handle_message(request: Multipart) -> Multipart {
    let mut response = Multipart::new();
    for msg in request {
        let msg_str = msg.as_str().unwrap();
        let req: IpcRequest = serde_json::from_str(msg_str).unwrap();
        match req {
            IpcRequest::GetRegistrationParams{id} => (),
            IpcRequest::IdentityChallenge{id, nonce} => (),
            IpcRequest::GetTip{id, input} => (),
            IpcRequest::GetTips{id, input} => (),
            IpcRequest::GetAllTips{id} => (),
            IpcRequest::GetAllAddrs{id} => (),
            IpcRequest::GetDelta{id, input} => (),
            IpcRequest::GetDeltas{id, input} => (),
            IpcRequest::GetContract{id, input} => (),
            IpcRequest::UpdateNewContract{id, address, bytecode} => (),
            IpcRequest::UpdateDeltas{id, deltas} => (),
        }


//        let _res = to_vec(&___).unwrap();
//        let res_msg = Message::from_slice(&_res).unwrap();
//        response.push_back(res_msg);
    }
    response
}