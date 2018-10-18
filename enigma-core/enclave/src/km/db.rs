use enigma_runtime_t::data::{StatePatch, EncryptedPatch, Encryption};
use common::utils_t::Sha256;

pub fn encrypt_delta(del: StatePatch) -> EncryptedPatch {
    let key = get_delta_key();
    del.encrypt(&key).unwrap()
}

pub fn get_delta_key() -> [u8;32] {
    b"Enigma".sha256()
}