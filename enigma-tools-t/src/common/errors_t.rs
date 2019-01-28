use enigma_types::{EnclaveReturn, ResultToEnclaveReturn};

use json_patch;
use pwasm_utils as wasm_utils;
use sgx_types::sgx_status_t;
use enigma_crypto::CryptoError;
use std::str;
use std::string::{String, ToString};
use wasmi::{self, TrapKind};

#[derive(Debug, Fail)]
pub enum EnclaveError {
    #[fail(display = "Cryptography Error: {:?}", err)]
    CryptoError { err: CryptoError },

    #[fail(display = "Preprocessor Error: {}", message)]
    PreprocessorError { message: String },

    #[fail(display = "Input Error: {}", message)]
    InputError { message: String },

    #[fail(display = "There's no sufficient permissions to read this file: {}", file)]
    PermissionError { file: String },

    #[fail(display = "An SGX Error has occurred: {}, Description: {}", err, description)]
    SgxError { err: String, description: String },

    #[fail(display = "Error in execution of {}: {}", code, err)]
    ExecutionError { code: String, err: String },

    #[fail(display = "Error in EVM:  {}", err)]
    EvmError { err: String },

    #[fail(display = "There's a State error with: {}", err)]
    StateError { err: String },

    #[fail(display = "There's an error with the ocall: {}; {}", command, err)]
    OcallError { command: String, err: String },

    #[fail(display = "UTF8 failure in a from_utf8: {}", err)]
    Utf8Error { err: String },

    #[fail(display = "There's an error with the messaging: {}", err)]
    MessagingError { err: String },
}

impl From<CryptoError> for EnclaveError {
    fn from(err: CryptoError) -> EnclaveError {
        EnclaveError::CryptoError { err }
    }
}

impl From<sgx_status_t> for EnclaveError {
    fn from(err: sgx_status_t) -> EnclaveError {
        EnclaveError::SgxError { err: err.as_str().to_string(), description: err.__description().to_string() }
    }
}

impl From<rmp_serde::decode::Error> for EnclaveError {
    fn from(err: rmp_serde::decode::Error) -> EnclaveError { EnclaveError::StateError { err: format!("{:?}", err) } }
}

impl From<rmp_serde::encode::Error> for EnclaveError {
    fn from(err: rmp_serde::encode::Error) -> EnclaveError { EnclaveError::StateError { err: format!("{:?}", err) } }
}

impl From<json_patch::PatchError> for EnclaveError {
    fn from(err: json_patch::PatchError) -> EnclaveError { EnclaveError::StateError { err: format!("{}", err) } }
}

impl From<wasmi::Trap> for EnclaveError {
    fn from(trap: wasmi::Trap) -> Self {
        match *trap.kind() {
            TrapKind::Unreachable => EnclaveError::ExecutionError { code: "".to_string(), err: "unreachable".to_string() },
            TrapKind::MemoryAccessOutOfBounds => {
                EnclaveError::ExecutionError { code: "".to_string(), err: "memory access out of bounds".to_string() }
            }
            TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => {
                EnclaveError::ExecutionError { code: "".to_string(), err: "table access out of bounds".to_string() }
            }
            TrapKind::DivisionByZero => EnclaveError::ExecutionError { code: "".to_string(), err: "division by zero".to_string() },
            TrapKind::InvalidConversionToInt => {
                EnclaveError::ExecutionError { code: "".to_string(), err: "invalid conversion to int".to_string() }
            }
            TrapKind::UnexpectedSignature => {
                EnclaveError::ExecutionError { code: "".to_string(), err: "unexpected signature".to_string() }
            }
            TrapKind::StackOverflow => EnclaveError::ExecutionError { code: "".to_string(), err: "stack overflow".to_string() },
            TrapKind::Host(_) => EnclaveError::ExecutionError { code: "".to_string(), err: trap.to_string() },
        }
    }
}

impl From<str::Utf8Error> for EnclaveError {
    fn from(err: str::Utf8Error) -> Self { EnclaveError::Utf8Error { err: format!("{:?}", err) } }
}

impl From<hexutil::ParseHexError> for EnclaveError {
    fn from(err: hexutil::ParseHexError) -> Self { EnclaveError::InputError { message: format!("{:?}", err) } }
}


impl Into<EnclaveReturn> for EnclaveError {
    fn into(self) -> EnclaveReturn {
        use self::EnclaveError::*;
        use self::CryptoError::*;
        match self {
            InputError { .. } | PreprocessorError { .. } => EnclaveReturn::InputError,
            PermissionError { .. } => EnclaveReturn::PermissionError,
            SgxError { .. } => EnclaveReturn::SgxError,
            ExecutionError { .. } => EnclaveReturn::WasmError,
            StateError { .. } => EnclaveReturn::StateError,
            OcallError { .. } => EnclaveReturn::OcallError,
            Utf8Error { .. } => EnclaveReturn::Utf8Error,
            EvmError { .. } => EnclaveReturn::EVMError,
            MessagingError { .. } => EnclaveReturn::MessagingError,
            CryptoError{err} => match err {
                IoError { .. } => EnclaveReturn::Other,
                RandomError { .. } => EnclaveReturn::SgxError,
                DerivingKeyError { .. } | KeyError { .. }  => EnclaveReturn::KeysError,
                DecryptionError { .. } | EncryptionError { .. } | SigningError { .. } | ImproperEncryption => EnclaveReturn::EncryptionError,
            }
        }
    }
}

impl ResultToEnclaveReturn for EnclaveError {
    fn into_enclave_return(self) -> EnclaveReturn { self.into() }
}

impl From<parity_wasm::elements::Error> for EnclaveError {
    fn from(err: parity_wasm::elements::Error) -> EnclaveError {
        EnclaveError::ExecutionError { code: "parity_wasm".to_string(), err: err.to_string() }
    }
}

impl From<parity_wasm::elements::Module> for EnclaveError {
    fn from(_err: parity_wasm::elements::Module) -> EnclaveError {
        EnclaveError::ExecutionError { code: "inject gas counter".to_string(), err: "".to_string() }
    }
}

impl From<wasm_utils::stack_height::Error> for EnclaveError {
    fn from(err: wasm_utils::stack_height::Error) -> EnclaveError {
        EnclaveError::ExecutionError { code: "inject stack height limiter".to_string(), err: format!("{:?}", err) }
    }
}

impl From<wasmi::Error> for EnclaveError {
    fn from(err: wasmi::Error) -> EnclaveError {
        EnclaveError::ExecutionError { code: "convert to wasm module".to_string(), err: format!("{:?}", err) }
    }
}
