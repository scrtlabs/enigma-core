#![allow(dead_code,unused_assignments,unused_variables)]
use std::io;
use std::string::String;

#[derive(Debug, Fail)]
pub enum EnclaveError {
    #[fail(display = "Failed to derive a key with ECDH: self: {}, other: {}", self_key, other_key)]
    DerivingKeyErr {
        self_key: String,
        other_key: String,
    },
    #[fail(display = "The {} Isn't valid: {}", key_type, key)]
    KeyErr {
        key_type: String,
        key: String,
    },
    #[fail(display = "Failed Decrypting: {}", encrypted_parm)]
    DecryptionError {
        encrypted_parm: String,
    },
}