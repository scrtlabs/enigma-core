use std::vec::Vec;
use ethereum_types::{U256,H160};

pub const ONE: u8 = 1;
pub const ZERO: u8 = 0;
/// implements the serialization for types needed for epoch encoding in the KM node,
/// according to this proof: https://github.com/enigmampc/protocol-discovery/blob/master/docs/hash_mul_nested.pdf
pub trait NestedSerialization {
    fn hash_encode(&self) -> (usize, Vec<u8>);
}

impl NestedSerialization for U256 {
    fn hash_encode(&self) -> (usize, Vec<u8>) {
        let mut res: Vec<u8> = Vec::new();
        let mut msg = [0u8;32];

        self.to_big_endian(&mut msg);
        let len = msg.len().to_be_bytes();

        res.push(ZERO);
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
        (msg.len(), res)
    }
}

impl NestedSerialization for H160 {
    fn hash_encode(&self) -> (usize, Vec<u8>) {
        let mut res: Vec<u8> = Vec::new();
        let msg: &[u8] = self.as_ref();
        let len = msg.len().to_be_bytes();

        res.push(ZERO);
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
        (msg.len(), res)
    }
}

impl <T: NestedSerialization> NestedSerialization for Vec<T> {
    fn hash_encode(&self) -> (usize, Vec<u8>) {
        let mut res: Vec<u8> = Vec::new();
        let mut messages = Vec::new();
        let mut res_len: usize = 0;

        for value in self.iter() {
            let (len, msg) = value.hash_encode();
            res_len += len;
            messages.extend_from_slice(&msg);
        }

        let final_len = res_len.to_be_bytes();
        res.push(ONE);
        res.extend_from_slice(&final_len);
        res.extend_from_slice(&messages);
        (res_len, res)
    }
}