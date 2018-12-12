use std::sync::Arc;
use futures::Future;
use tokio_zmq::{Rep, Multipart, Error};
use tokio_zmq::prelude::*;
use crate::networking::messages::*;

pub struct IpcListener {
    context: Arc<zmq::Context>,
    rep_future: Box<Future<Item=Rep, Error=Error>>,

}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(context.clone()).bind(conn_str).build();
        IpcListener { context, rep_future }
    }

    pub fn run<F, B>(self, f: F) -> impl Future<Item =(), Error = Error>
        where F: Fn(Multipart) -> Multipart {

        let runner = self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f)
                .forward(sink)
                .map(|(_stream, _sink)| ())
        });
        runner
    }
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