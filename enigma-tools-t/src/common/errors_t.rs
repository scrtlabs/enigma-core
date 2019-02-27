use enigma_types::{EnclaveReturn, ResultToEnclaveReturn};

use json_patch;
use pwasm_utils as wasm_utils;
use sgx_types::sgx_status_t;
use enigma_crypto::CryptoError;
use std::str;
use std::string::{String, ToString};
use wasmi::{self, TrapKind};
use parity_wasm;

// Error of WASM execution by wasmi or runtime
#[derive(Debug)]
pub enum WasmError {
    GasLimit,
    WasmiError(wasmi::Error),
    EnclaveError(EnclaveError),
}

// Trait that allows to return custom error from execution of  wasmi
impl wasmi::HostError for WasmError {}

// Implementation of Display is required by wasmi::HostError
impl ::std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match self {
            WasmError::GasLimit => write!(f, "Invocation resulted in gas limit violated"),
            WasmError::WasmiError(ref e) => write!(f, "{}", e),
            WasmError::EnclaveError(ref e) => write!(f, "{}", e),
        }
    }
}

// This is for call to wasmi functions from eng runtime
// Here the wasmi::Error exact type is lost and the error description may be not so clear
// It seems to be enough for now since the only wasmi functions called from eng runtime are:
// memory manipulation function.
impl From<wasmi::Error> for WasmError {
    fn from(e: wasmi::Error) -> Self {
        WasmError::WasmiError(e)
    }
}

// This is for extracting arguments in eng runtime
// Implemented by wasmi in `nth_checked` function
impl From<wasmi::Trap> for WasmError {
    fn from(trap: wasmi::Trap) -> Self { WasmError::WasmiError(wasmi::Error::Trap(trap)) }
}

// This is for any call from eng runtime to core function
// The EnclaveError is converted to WasmError::EnclaveError to ve extracted later as is
impl From<EnclaveError> for WasmError {
    fn from(err: EnclaveError) -> Self {
        WasmError::EnclaveError(err)
    }
}

impl From<parity_wasm::elements::Error> for EnclaveError {
    fn from(err: parity_wasm::elements::Error) -> EnclaveError {
        EnclaveError::WasmModuleError { code: "deserialization into WASM module".to_string(), err: err.to_string() }
    }
}

impl From<parity_wasm::elements::Module> for EnclaveError {
    fn from(err: parity_wasm::elements::Module) -> EnclaveError {
        EnclaveError::WasmModuleError { code: "injecting gas counter".to_string(), err: format!("{:?}", err) }
    }
}

impl From<wasm_utils::stack_height::Error> for EnclaveError {
    fn from(err: wasm_utils::stack_height::Error) -> EnclaveError {
        EnclaveError::WasmModuleError { code: "injecting stack height limiter".to_string(), err: format!("{:?}", err) }
    }
}

// This is for final conversion from the result of wasmi execution to core result
impl From<wasmi::Error> for EnclaveError{
    fn from(e: wasmi::Error) -> Self {
        match e {
            wasmi::Error::Trap(kind) => {
                match kind.kind() {
                    TrapKind::Host(t) => {
                        match (**t).downcast_ref::<WasmError>()
                            .expect("Failed to downcast to expected error type"){
                            WasmError::GasLimit => EnclaveError::GasLimitError,
                            WasmError::WasmiError(e) => EnclaveError::WasmCodeExecutionError { err: format!("{}", e) },
                            WasmError::EnclaveError(err) => err.clone(),
                        }
                    },
                    TrapKind::Unreachable => EnclaveError::WasmCodeExecutionError{ err: "unreachable".to_string() },
                    TrapKind::MemoryAccessOutOfBounds => EnclaveError::WasmCodeExecutionError{ err: "memory access out of bounds".to_string() },
                    TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => EnclaveError::WasmCodeExecutionError{ err: "table access out of bounds".to_string() },
                    TrapKind::DivisionByZero => EnclaveError::WasmCodeExecutionError{ err: "division by zero".to_string() },
                    TrapKind::InvalidConversionToInt => EnclaveError::WasmCodeExecutionError{ err: "invalid conversion to int".to_string() },
                    TrapKind::UnexpectedSignature => EnclaveError::WasmCodeExecutionError{ err: "unexpected signature".to_string() },
                    TrapKind::StackOverflow => EnclaveError::WasmCodeExecutionError{ err: "stack overflow".to_string() },
                }
            }
            _ => EnclaveError::WasmCodeExecutionError { err: e.to_string() }
        }
    }
}

#[derive(Debug, Fail, Clone)]
pub enum EnclaveError {
    #[fail(display = "Cryptography Error: {:?}", err)]
    CryptoError { err: CryptoError },

    #[fail(display = "Input Error: {}", message)]
    InputError { message: String },

    #[fail(display = "There's no sufficient permissions to read this file: {}", file)]
    PermissionError { file: String },

    #[fail(display = "An SGX Error has occurred: {}, Description: {}", err, description)]
    SgxError { err: String, description: String },

    #[fail(display = "Error in execution of {}: {}", code, err)]
    WasmModuleError { code: String, err: String },

    #[fail(display = "Error in execution of WASM code: {}", err)]
    WasmCodeExecutionError { err: String},

    #[fail(display = "Invocation resulted in gas limit violated")]
    GasLimitError,

    #[fail(display = "Error in EVM:  {}", err)]
    EvmError { err: String },

    #[fail(display = "There's a State error with: {}", err)]
    StateError { err: String },

    #[fail(display = "There's an error with the ocall: {}; {}", command, err)]
    OcallError { command: String, err: String },

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

impl From<str::Utf8Error> for EnclaveError {
    fn from(err: str::Utf8Error) -> Self { EnclaveError::InputError { message: format!("{:?}", err) } }
}

impl From<hexutil::ParseHexError> for EnclaveError {
    fn from(err: hexutil::ParseHexError) -> Self { EnclaveError::InputError { message: format!("{:?}", err) } }
}

impl ResultToEnclaveReturn for EnclaveError {
    fn into_enclave_return(self) -> EnclaveReturn { self.into() }
}

impl Into<EnclaveReturn> for EnclaveError {
    fn into(self) -> EnclaveReturn {
        use self::EnclaveError::*;
        use self::CryptoError::*;
        match self {
            InputError { .. } => EnclaveReturn::InputError,
            PermissionError { .. } => EnclaveReturn::PermissionError,
            SgxError { .. } => EnclaveReturn::SgxError,
            WasmModuleError { .. } => EnclaveReturn::WasmModuleError,
            StateError { .. } => EnclaveReturn::StateError,
            OcallError { .. } => EnclaveReturn::OcallError,
            EvmError { .. } => EnclaveReturn::EVMError,
            MessagingError { .. } => EnclaveReturn::MessagingError,
            CryptoError{err} => match err {
                RandomError { .. } => EnclaveReturn::SgxError,
                DerivingKeyError { .. } | KeyError { .. } | MissingKeyError { .. } => EnclaveReturn::KeysError,
                DecryptionError { .. } | EncryptionError { .. } | SigningError { .. } | ImproperEncryption |
                ParsingError { ..} | RecoveryError { .. } => EnclaveReturn::EncryptionError,
            }
            WasmCodeExecutionError { .. } => EnclaveReturn::WasmCodeExecutionError,
            GasLimitError => EnclaveReturn::GasLimitError,
        }
    }
}

