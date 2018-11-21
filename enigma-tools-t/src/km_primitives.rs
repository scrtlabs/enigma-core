#![allow(dead_code)]
use crate::common::errors_t::EnclaveError;
use std::vec::Vec;
use sgx_trts::trts::rsgx_read_rand;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

pub type StateKey = Vec<u8>;
pub type ContractAddress = [u8; 32];
pub type MsgID = [u8; 12];
pub type PubKey = [u8; 64];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Response(Vec<(ContractAddress, StateKey)>),
    Request(Vec<ContractAddress>)
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Message {
    #[doc(hidden)]
    prefix: [u8; 14],
    data: MessageType,
    pubkey: Vec<u8>,
    id: MsgID,
}

impl Message {
    const PREFIX: &'static [u8; 14] = b"Enigma Message";

    pub fn new(data: MessageType, pubkey: PubKey) -> Result<Message, EnclaveError> {
        let mut id = [0u8; 12];
        rsgx_read_rand(&mut id)?;
        let pubkey = pubkey.to_vec();
        let prefix = *Self::PREFIX;
        Ok(Message { data, pubkey, id, prefix })
    }

    pub fn new_id(data: MessageType, id: [u8; 12], pubkey: PubKey) -> Message {
        let pubkey = pubkey.to_vec();
        let prefix = *Self::PREFIX;
        Message { data, pubkey, id, prefix }
    }

    pub fn to_message(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        let val = serde_json::to_value(self.clone()).unwrap();
        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_message(msg: &[u8]) -> Result<Message, EnclaveError> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)?;
        let msg: Message = serde_json::from_value(res).unwrap();
        Ok(msg)
    }

    pub fn get_id(&self) -> MsgID { self.id }
}

pub mod tests {
    use super::{Message, MessageType};
    pub fn test_to_message() {
        let data = MessageType::Request(vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];
        let res = Message::new_id(data, id, [0u8; 64]);
        assert_eq!(res.to_message().unwrap(), vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    pub fn test_from_message() {
        let msg = [132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = MessageType::Request(vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        assert_eq!(Message::new_id(data, id, [0u8;64]), Message::from_message(&msg[..]).unwrap());
    }

    pub fn test_from_to_message() {
        let data = MessageType::Request(vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];
        let res = Message::new_id(data, id, [0u8; 64]);
        let msg = res.to_message().unwrap();

        assert_eq!(Message::from_message(&msg[..]).unwrap(), res);
    }
}