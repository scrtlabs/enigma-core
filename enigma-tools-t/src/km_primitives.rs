#![allow(dead_code)]
use crate::common::errors_t::EnclaveError;
use std::vec::Vec;
use sgx_trts::trts::rsgx_read_rand;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

pub type StateKey = Vec<u8>;
pub type ContractAddress = [u8; 32];
type MsgID = [u8; 12];


#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
struct Request {
    addresses: Vec<ContractAddress>,
    id: MsgID,
}

impl Request {
    const PREFIX: &'static [u8; 36] = b"Requesting keys for these contracts:";

    pub fn new(addresses: Vec<ContractAddress>) -> Result<Request, EnclaveError> {
        let mut id = [0u8; 12];
        rsgx_read_rand(&mut id)?;
        Ok(Request { addresses, id })
    }

    pub fn new_id(addresses: Vec<ContractAddress>, id: [u8; 12]) -> Request {
        Request { addresses, id }
    }

    pub fn to_message(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        buf.extend(&Self::PREFIX[..]);
        let val = serde_json::to_value(self.clone()).unwrap();
        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_message(msg: &[u8]) -> Result<Request, EnclaveError> {
        let mut des = Deserializer::new(&msg[Self::PREFIX.len()..]);
        let res: Request = Deserialize::deserialize(&mut des)?;
        Ok(res)
    }
}

pub mod tests {
    use super::Request;
    pub fn test_to_message() {
        let addresses = vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ];
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];
        let res = Request::new_id(addresses, id);

        assert_eq!(res.to_message().unwrap(), vec![82, 101, 113, 117, 101, 115, 116, 105, 110, 103, 32, 107, 101, 121, 115, 32, 102, 111, 114, 32, 116, 104, 101, 115, 101, 32, 99, 111, 110, 116, 114, 97, 99, 116, 115, 58, 130, 169, 97, 100, 100, 114, 101, 115, 115, 101, 115, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231]);
    }

    pub fn test_from_message() {
        let msg = [82, 101, 113, 117, 101, 115, 116, 105, 110, 103, 32, 107, 101, 121, 115, 32, 102, 111, 114, 32, 116, 104, 101, 115, 101, 32, 99, 111, 110, 116, 114, 97, 99, 116, 115, 58, 130, 169, 97, 100, 100, 114, 101, 115, 115, 101, 115, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231];
        let addresses = vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ];
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        assert_eq!(Request::new_id(addresses, id), Request::from_message(&msg[..]).unwrap());
    }

    pub fn test_from_to_message() {
        let addresses = vec![ [0u8;32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8;32] ];
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];
        let res = Request::new_id(addresses, id);
        let msg = res.to_message().unwrap();

        assert_eq!(Request::from_message(&msg[..]).unwrap(), res);
    }
}