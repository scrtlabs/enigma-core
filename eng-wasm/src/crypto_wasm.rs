use super::*;

use rand_wasm::Rand;
use eng_pwasm_abi::types::U256;

const SYMMETRIC_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 96 / 8;
const PAYLOAD_SIZE: usize = 1024;

pub type IV = [u8; IV_SIZE];
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

pub fn generate_key() -> SymmetricKey {
    let key_int: U256 = Rand::gen();
    let key = H256::from(key_int);
    key.0
}

pub fn encrypt(message: &[u8], key: &SymmetricKey) -> Vec<u8> {
    // TODO: Is this really needed? Dynamically sized buffers don't seem to work.
    // TODO: Is it possible to estimate the encrypted payload size based on the plaintext message?
    let length = PAYLOAD_SIZE;
    let mut payload = Vec::with_capacity(length);
    for _ in 0..length {
        payload.push(0);
    }
    unsafe { external::encrypt(message.as_ptr(), message.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    // Finding the end of trailing zeros
    let mut end = 0;
    for i in (0..length).rev() {
        if payload[i] != 0 {
            // Range selectors exclude the upper bound
            end = i + 1;
            break;
        }
    }
    payload[0..end].to_vec()
}

pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Vec<u8> {
    // Assuming that plaintext messages cannot be shorter that their encrypted cipher
    // TODO: Some unnecessary bytes can be subtracted from the buffer, at least the IV size.
    let length: usize = cipheriv.len();
    let mut payload = Vec::with_capacity(length);
    for _ in 0..length {
        payload.push(0);
    }
    unsafe { external::decrypt(cipheriv.as_ptr(), cipheriv.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    let mut end = 0;
    for i in (0..length).rev() {
        if payload[i] != 0 {
            end = i + 1;
            break;
        }
    }
    payload[0..end].to_vec()
}
