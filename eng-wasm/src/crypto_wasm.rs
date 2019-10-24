use super::*;

use eng_pwasm_abi::types::U256;
use rand_wasm::Rand;

const SYMMETRIC_KEY_SIZE: usize = 32;

pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

fn extra_size_for_cypher() -> usize {
    unsafe {(external::get_iv_size() + external:: get_tag_size()) as usize }
}


pub fn generate_key() -> SymmetricKey {
    let key_int: U256 = Rand::gen();
    let key = H256::from(key_int);
    key.0
}

pub fn encrypt(message: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let length = message.len() + extra_size_for_cypher();
    let mut payload = vec![0u8; length];
    unsafe { external::encrypt(message.as_ptr(), message.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload.to_vec()
}

pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let length = cipheriv.len() - extra_size_for_cypher();
    let mut payload = vec![0u8; length];
    unsafe { external::decrypt(cipheriv.as_ptr(), cipheriv.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload.to_vec()
}
