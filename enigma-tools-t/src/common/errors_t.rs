use std::string::{String, ToString};
use sgx_types::sgx_status_t;
use rmps;
use json_patch;
use wasmi::{self, TrapKind};
use std::str;

#[derive(Debug, Fail)]
pub enum EnclaveError {
    #[fail(display = "Failed to derive a key with ECDH: self: {}, other: {}", self_key, other_key)]
    DerivingKeyError {
        self_key: String,
        other_key: String,
    },
    #[fail(display = "The {} Isn't valid: {}", key_type, key)]
    KeyError {
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
    SigningError {
        msg: String,
    },
    #[fail(display = "There's no sufficient permissions to read this file: {}", file)]
    PermissionError {
        file: String,
    },
    #[fail(display = "Failed Generating a: {}, {}", generate, err)]
    GenerationError {
        generate: String,
        err: String,
    },
    #[fail(display = "An SGX Error has occurred: {}, Description: {}", err, description)]
    SgxError {
        err: String,
        description: String,
    },
    #[fail(display = "Error in execution of {}: {}", code, err)]
    ExecutionError {
        code: String,
        err: String,
    },
    #[fail(display = "There's a State error with: {}", err)]
    StateError {
        err: String,
    },
    #[fail(display = "There's an error with the ocall: {}; {}", command, err)]
    OcallError {
        command: String,
        err: String,
    }

}

impl From<sgx_status_t> for EnclaveError {
    fn from(err: sgx_status_t) -> EnclaveError {
        EnclaveError::SgxError { err: err.as_str().to_string(), description: err.__description().to_string() }
    }
}

impl From<rmps::decode::Error> for EnclaveError {
    fn from(err: rmps::decode::Error) -> EnclaveError {
        EnclaveError::StateError { err: format!("{:?}", err)}
    }
}

impl From<rmps::encode::Error> for EnclaveError {
    fn from(err: rmps::encode::Error) -> EnclaveError {
        EnclaveError::StateError { err: format!("{:?}", err)}
    }
}

impl From<json_patch::PatchError> for EnclaveError {
    fn from(err: json_patch::PatchError) -> EnclaveError {
        EnclaveError::StateError { err: format!("{}", err) }
    }
}

impl From<wasmi::Trap> for EnclaveError {
    fn from(trap: wasmi::Trap) -> Self {
        match *trap.kind() {
            TrapKind::Unreachable => EnclaveError::ExecutionError {code: "".to_string(), err: "unreachable".to_string()},
            TrapKind::MemoryAccessOutOfBounds => EnclaveError::ExecutionError {code: "".to_string(), err: "memory access out of bounds".to_string()},
            TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => EnclaveError::ExecutionError {code: "".to_string(), err: "table access out of bounds".to_string()},
            TrapKind::DivisionByZero => EnclaveError::ExecutionError {code: "".to_string(), err: "division by zero".to_string()},
            TrapKind::InvalidConversionToInt => EnclaveError::ExecutionError {code: "".to_string(), err: "invalid conversion to int".to_string()},
            TrapKind::UnexpectedSignature => EnclaveError::ExecutionError {code: "".to_string(), err: "unexpected signature".to_string()},
            TrapKind::StackOverflow => EnclaveError::ExecutionError {code: "".to_string(), err: "stack overflow".to_string()},
        }
    }
}

impl From<str::Utf8Error> for EnclaveError {
    fn from(err: str::Utf8Error) -> Self {
        EnclaveError::ExecutionErr { code: "Failed formatting utf-8 in Runtime".to_string(), err: format!("{:?}", err) }
    }
}
