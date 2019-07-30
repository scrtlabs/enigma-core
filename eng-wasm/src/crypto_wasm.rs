use super::*;

const SYMMETRIC_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 96 / 8;
pub type IV = [u8; IV_SIZE];
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

pub struct Crypto;

impl Crypto {
    fn encrypt_with_nonce(message: &[u8], key: &SymmetricKey, iv: &IV, payload: &mut [u8]) {
        unsafe { external::encrypt_with_nonce(message.as_ptr(), message.len() as u32, key.as_ptr(), iv.as_ptr(), payload.as_ptr()) };
    }
    fn decrypt(cipheriv: &[u8], key: &SymmetricKey, payload: &mut [u8]) {
        unsafe { external::decrypt(cipheriv.as_ptr(), cipheriv.len() as u32, key.as_ptr(), payload.as_ptr()) };
    }
}
