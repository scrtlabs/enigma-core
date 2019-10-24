use super::*;

use eng_pwasm_abi::types::U256;
use rand_wasm::Rand;

const SYMMETRIC_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 96 / 8;
const TAG_SIZE: usize = 16;

pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

pub fn generate_key() -> SymmetricKey {
    let key_int: U256 = Rand::gen();
    let key = H256::from(key_int);
    key.0
}

pub fn encrypt(message: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let length = message.len() + IV_SIZE + TAG_SIZE;
    let mut payload = vec![0u8; length];
    unsafe { external::encrypt(message.as_ptr(), message.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload.to_vec()
}

pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let length: usize = cipheriv.len() - IV_SIZE - TAG_SIZE;
    let mut payload = vec![0u8; length];
    unsafe { external::decrypt(cipheriv.as_ptr(), cipheriv.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload.to_vec()
}
