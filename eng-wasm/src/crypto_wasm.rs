/// Wrapper for the Enigma runtime service for symmetric ASM-256-GCM encryption/decryption
/// The encrypted text contains the IV, cyphertext, and authentication tag
/// In AES-GCM the length of cyphertext is identical to the length of plain text

use super::*;

use eng_pwasm_abi::types::U256;
use rand_wasm::Rand;

const SYMMETRIC_KEY_SIZE: usize = 256 / 8;
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];
const AES_256_GCM_TAG_SIZE: usize = 16;
const AES_256_GCM_IV_SIZE: usize = 96 / 8;


/// The extra length (IV and authentication tag) of the encryption result
fn extra_size_for_encrypted_text() -> usize {
    unsafe {AES_256_GCM_IV_SIZE + AES_256_GCM_TAG_SIZE}
}


pub fn generate_key() -> SymmetricKey {
    let key_int: U256 = Rand::gen();
    let key = H256::from(key_int);
    key.0
}

pub fn encrypt(message: &[u8], key: &SymmetricKey) -> Vec<u8> {
    // The length of the buffer containing encrypted text
    let length = message.len().checked_add(extra_size_for_encrypted_text()).expect("Overflow in encrypted message length");
    // The buffer containing encrypted text
    let mut payload = vec![0u8; length];
    // Call to the runtime service to encrypt
    unsafe { external::encrypt(message.as_ptr(), message.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload
}

pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Vec<u8> {
    // The length of the plaintext
    let length = cipheriv.len().checked_sub(extra_size_for_encrypted_text()).expect("Overflow in encrypted message length");
    // The buffer for the plaintext
    let mut payload = vec![0u8; length];
    // Call to the runtime service to decrypt
    unsafe { external::decrypt(cipheriv.as_ptr(), cipheriv.len() as u32, key.as_ptr(), payload.as_mut_ptr()) };
    payload
}
