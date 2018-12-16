use std::sync::Arc;
use futures::{Future, Stream};
use tokio_zmq::{Rep, Multipart, Error};
use tokio_zmq::prelude::*;
use zmq::Message;
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

    pub fn run<F>(self, f: F) -> impl Future<Item =(), Error = Error>
        where F: Fn(Multipart) -> Multipart {

        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f)
                .forward(sink)
                .map(|(_stream, _sink)| ())
        })
    }
}

fn handle_message(request: Multipart) -> Multipart {
    let mut response = Multipart::new();
    for msg in request {
        let response_msg: Message = match msg.into() {
            IpcRequest::GetRegistrationParams{id} => handling::get_registration_params(id),
            IpcRequest::IdentityChallenge{id, nonce} => handling::identity_challange(id, nonce),
            IpcRequest::GetTip{id, input} => handling::get_tip(id, input),
            IpcRequest::GetTips{id, input} => handling::get_tips(id, input),
            IpcRequest::GetAllTips{id} => handling::get_all_tips(id),
            IpcRequest::GetAllAddrs{id} => handling::get_all_addrs(id),
            IpcRequest::GetDelta{id, input} => handling::get_delta(id, input),
            IpcRequest::GetDeltas{id, input} => handling::get_deltas(id, input),
            IpcRequest::GetContract{id, input} => handling::get_contract(id, input),
            IpcRequest::UpdateNewContract{id, address, bytecode} => handling::update_new_contract(id, address, bytecode),
            IpcRequest::UpdateDeltas{id, deltas} => handling::update_deltas(id, deltas),
        };

        response.push_back(response_msg);
    }
    response
}


pub(self) mod handling {
    use zmq::Message;
    use enigma_tools_u::common_u::{LockExpectMutex, FromHex32};
    use hex::{FromHex, ToHex};
    use crate::db::{DATABASE, P2PCalls, DeltaKey, Stype, CRUDInterface};
    use crate::networking::messages::*;

    pub fn get_registration_params(id: String) -> Message {
        Message::new().unwrap()
    }

    pub fn identity_challange(id: String, nonce: String) -> Message {
        Message::new().unwrap()
    }

    pub fn get_tip(id: String, input: String) -> Message {
        let mut address = [0u8; 32];
        address.copy_from_slice(&input.from_hex().unwrap());
        let (tip_key, tip_data) = DATABASE.lock_expect("P2P, GetTip").get_tip::<DeltaKey>(&address).unwrap();
        if let Stype::Delta(key) = tip_key.key_type {
            let delta = IpcDelta { address: None, key, delta: Some(tip_data.to_hex()) };
            IpcResponse::GetTip { id, result: delta }.into()
        } else { unreachable!() }
    }

    pub fn get_tips(id: String, input: Vec<String>) -> Message {
        let address_iter = input.into_iter()
            .map(|input| input.from_hex_32().unwrap() );

        let mut tips_results = Vec::with_capacity(address_iter.len());
        for address in address_iter {
            let (tip_key, tip_data) = DATABASE.lock_expect("P2P, GetTips").get_tip::<DeltaKey>(&address).unwrap();
            if let Stype::Delta(indx) = tip_key.key_type {
                let delta = IpcDelta { address: Some(address.to_hex()), key: indx, delta: Some(tip_data.to_hex()) };
                tips_results.push(delta);
            } else { unreachable!() }
        }
        IpcResponse::GetTips { id, result: IpcResults::Tips(tips_results) }.into()
    }

    pub fn get_all_tips(id: String) -> Message {
        let tips = DATABASE.lock_expect("P2P GetAllTips").get_all_tips::<DeltaKey>().unwrap();
        let mut tips_results = Vec::with_capacity(tips.len());
        for (key, data) in tips {
            if let Stype::Delta(indx) = key.key_type {
                let delta = IpcDelta { address: Some(key.hash.to_hex()), key: indx, delta: Some(data.to_hex()) };
                tips_results.push(delta);
            } else { unreachable!() }

        }
        IpcResponse::GetAllTips { id, result: tips_results }.into()
    }

    pub fn get_all_addrs(id: String) -> Message {
        let addresses: Vec<String> = DATABASE.lock_expect("P2P GetAllAddrs").get_all_addresses().unwrap()
            .iter().map(|addr| addr.to_hex()).collect();
        IpcResponse::GetAllAddrs { id, result: IpcResults::Addresses(addresses) }.into()
    }

    pub fn get_delta(id: String, input: IpcDelta) -> Message {
        let address = input.address.unwrap().from_hex_32().unwrap();
        let delta_key = DeltaKey::new(address, Stype::Delta(input.key));
        let delta = DATABASE.lock_expect("P2P GetDelta").get_delta(delta_key).unwrap();
        IpcResponse::GetDelta {id, result: IpcResults::Delta(delta.to_hex())}.into()
    }

    pub fn get_deltas(id: String, input: Vec<IpcGetDeltas>) -> Message {
        let deltas = input.iter().map(|data| {
            let address = data.address.from_hex_32().unwrap();
            let from = DeltaKey::new(address, Stype::Delta(data.from));
            let to = DeltaKey::new(address, Stype::Delta(data.to));
            (from, to)
        });
        let mut results = Vec::with_capacity(deltas.len());
        for (from, to) in deltas {
            for (key, data)  in DATABASE.lock_expect("P2P GetDeltas").get_deltas(from, to).unwrap().unwrap() {
                let address = key.hash.to_hex();
                if let Stype::Delta(indx) = key.key_type {
                    let delta = IpcDelta { address: Some(address), key: indx, delta: Some(data.to_hex()) };
                    results.push(delta);
                } else { unreachable!() }
            }
        }
        IpcResponse::GetDeltas {id, result: IpcResults::Deltas(results)}.into()
    }

    pub fn get_contract(id: String, input: String) -> Message {
        let address = input.from_hex_32().unwrap();
        let data = DATABASE.lock_expect("P2P GetContract").get_contract(address).unwrap();
        IpcResponse::GetContract {id, result: IpcResults::Bytecode(data.to_hex())}.into()
    }

    pub fn update_new_contract(id: String, address: String, bytecode: String) -> Message {
        let address_arr = address.from_hex_32().unwrap();
        let bytecode = bytecode.from_hex().unwrap();
        let delta_key = DeltaKey::new(address_arr, Stype::ByteCode);
        DATABASE.lock_expect("P2P UpdateNewContract").force_update(&delta_key, &bytecode).unwrap();
        IpcResponse::UpdateNewContract {id, address, result: IpcResults::Status("0".to_string())}.into()
    }

    pub fn update_deltas(id: String, deltas: Vec<IpcDelta>) -> Message {

        let tuples: Vec<(DeltaKey, Vec<u8>)> = deltas.into_iter().map(|delta| {
            let address = delta.address.unwrap().from_hex_32().unwrap();
            let data = delta.delta.unwrap().from_hex().unwrap();
            let delta_key = DeltaKey::new(address, Stype::Delta(delta.key));
            (delta_key, data)
        }).collect();
        let results = DATABASE.lock_expect("P2P UpdateDeltas").insert_tuples(&tuples);
        // TODO: do something with the results here, they don't match the logic of the other results, because of the namespace
        // TODO: not sure what's the best way to treat this, need to look into more features of serde-json or reevaluate the structure.
        let mut errors = Vec::with_capacity(tuples.len());

        for ((deltakey, _), res) in tuples.into_iter().zip(results.into_iter()) {
            match res {
                Ok(()) => {
                    if let Stype::Delta(indx) = deltakey.key_type {
                        let delta = IpcDeltaResult { address: deltakey.hash.to_hex(), key: indx, status: 0 };
                        errors.push(delta);
                    } else { unreachable!() }
                }
                Err(_) => {
                    if let Stype::Delta(indx) = deltakey.key_type {
                        let delta = IpcDeltaResult { address: deltakey.hash.to_hex(), key: indx, status: 1 };
                        errors.push(delta);
                    } else { unreachable!() }
                }
            }
        }
        IpcResponse::UpdateDeltas{ id, result: IpcUpdateDeltasResult { status: 0, errors } }.into()
    }

}


#[cfg(test)]
mod test {
    use super::*;
    #[ignore]
    #[test]
    fn test_the_listener() {
        let conn = "tcp://*:5556";
        let server = IpcListener::new(conn);
        server.run(|mul| {
            println!("{:?}", mul);
            mul
        }).wait();
    }

    #[test]
    fn test_response() {
        let results = vec![IpcDelta { address: Some("one".to_string()), key: 0, delta: Some("one".to_string()) },
                                        IpcDelta { address: Some("two".to_string()), key: 0, delta: Some("two".to_string()) },
        ];
        let id = String::from("fds423rw");
        let a = IpcResponse::GetDeltas {id, result: IpcResults::Deltas(results)};
        let b = serde_json::to_vec(&a).unwrap();
        let msg = Message::from_slice(&b).unwrap();
        println!("WOWO");
        println!("{:?}", msg.as_str().unwrap());
    }
}