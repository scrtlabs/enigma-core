use std::string::{String, ToString};
use sgx_types::sgx_status_t;

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
    #[fail(display = "Failed Encrypting")]
    EncryptionError {},

    #[fail(display = "Preprocessor Error: {}", message)]
    PreprocessorError{
        message: String,
    },
    #[fail(display = "Input Error: {}", message)]
    InputError {
        message: String,
    },
    #[fail(display = "Signing the message failed: {}", msg)]
    SigningErr {
        msg: String,
    },
    #[fail(display = "There's no sufficient permissions to read this file: {}", file)]
    PermissionErr {
        file: String,
    },
    #[fail(display = "Failed Generating a: {}, {}", generate, err)]
    GenerationErr {
        generate: String,
        err: String,
    },
    #[fail(display = "An SGX Error has occurred: {}, Description: {}", err, description)]
    SgxErr {
        err: String,
        description: String,
    },
    #[fail(display = "Error in execution of {}: {}", code, err)]
    ExecutionErr {
        code: String,
        err: String,
    }
}

impl From<sgx_status_t> for EnclaveError {
    fn from(err: sgx_status_t) -> EnclaveError {
        EnclaveError::SgxErr { err: err.as_str().to_string(), description: err.__description().to_string() }
    }
}