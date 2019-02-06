use failure::Fail;
use crate::localstd::string::String;
use crate::localstd::io;
#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Failed to derive a key with ECDH: self: {}, other: {}", self_key, other_key)]
    DerivingKeyError { self_key: String, other_key: String },

    #[fail(display = "The {} Isn't valid, err: {}", key_type, err)]
    KeyError { key_type: String, err: String },

    #[fail(display = "Failed Decrypting")]
    DecryptionError,

    #[fail(display = "Improper Encryption")]
    ImproperEncryption,

    #[fail(display = "Failed Encrypting")]
    EncryptionError,

    #[fail(display = "Signing the message failed: {}", msg)]
    SigningError { msg: String },

    #[fail(display = "Failed Generating a: {}", err)]
    RandomError { err: String },

    #[fail(display = "IO Failure: {:?}", err)]
    IoError { err: io::Error },
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> Self {
        CryptoError::IoError { err }
    }
}