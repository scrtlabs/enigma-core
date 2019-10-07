use std::vec::Vec;
use ethereum_types::{U256,H160};

pub const ONE: u8 = 1;
pub const ZERO: u8 = 0;
/// implements the serialization for types needed for epoch encoding in the KM node,
/// according to this proof: https://github.com/enigmampc/protocol-discovery/blob/master/docs/hash_mul_nested.pdf
pub trait NestedSerialization {
    fn hash_encode(&self) -> Vec<u8>;
}

impl NestedSerialization for U256 {
    fn hash_encode(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        let mut msg = [0u8;32];

        self.to_big_endian(&mut msg);
        let len = (msg.len() as u64).to_be_bytes();

        res.push(ZERO);
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
        res
    }
}

impl NestedSerialization for H160 {
    fn hash_encode(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        let msg: &[u8] = self.as_ref();
        let len = (msg.len() as u64).to_be_bytes();

        res.push(ZERO);
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
        res
    }
}

impl <T: NestedSerialization> NestedSerialization for Vec<T> {
    fn hash_encode(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        let mut messages = Vec::new();
        let mut res_len: usize = 0;

        for value in self.iter() {
            let msg = value.hash_encode();
            res_len += msg.len();
            messages.extend_from_slice(&msg);
        }

        let final_len = (res_len as u64).to_be_bytes();
        res.push(ONE);
        res.extend_from_slice(&final_len);
        res.extend_from_slice(&messages);
        res
    }
}

pub mod tests {
    use ethereum_types::{H160, U256};

    use super::*;

    pub fn test_u256_nested() {
        let expected_arr : Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24];
        let num = U256::from(24);
        let accepted_arr = num.hash_encode();
        assert_eq!(expected_arr, accepted_arr);
    }

    pub fn test_h160_nested() {
        let expected_arr : Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];
        let addr = H160::from([2u8; 20]);
        let accepted_arr = addr.hash_encode();
        assert_eq!(expected_arr, accepted_arr);
    }

    pub fn test_vec_u256_nested() {
        let expected_arr = vec![1, 0, 0, 0, 0, 0, 0, 0, 164, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 194, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 140, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 232];
        let vec_nums: Vec<U256> = vec![U256::from(2498), U256::from(243), U256::from(2444), U256::from(21224)];
        let accepted_arr = vec_nums.hash_encode();
        assert_eq!(expected_arr, accepted_arr);
    }

    pub fn test_double_nested_vec_h160() {
        let expected_arr = vec![1, 0, 0, 0, 0, 0, 0, 0, 125, 1, 0, 0, 0, 0, 0, 0, 0, 116, 0, 0, 0, 0, 0, 0, 0, 0, 20, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 0, 0, 0, 0, 0, 0, 0, 0, 20, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 0, 0, 0, 0, 0, 0, 0, 0, 20, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 0, 0, 0, 0, 0, 0, 0, 0, 20, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231];
        let vec_vec_addr: Vec<Vec<H160>> = vec![vec![H160::from([17u8; 20]), H160::from([41u8; 20]), H160::from([12u8; 20]), H160::from([231u8; 20])]];
        let accepted_arr = vec_vec_addr.hash_encode();
        assert_eq!(expected_arr, accepted_arr);
    }
}