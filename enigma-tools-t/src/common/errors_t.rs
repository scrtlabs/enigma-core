use enigma_types::{EnclaveReturn, ResultToEnclaveReturn};
use enigma_tools_m::ToolsError;
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

// From `CryptoError` raised by `eng_crypto`
impl From<CryptoError> for WasmError {
    fn from(err: CryptoError) -> Self {
        WasmError::EnclaveError(EnclaveError::SystemError(EnclaveSystemError::CryptoError { err }))
    }
}

impl From<parity_wasm::elements::Error> for EnclaveError {
    fn from(err: parity_wasm::elements::Error) -> EnclaveError {
        EnclaveError::FailedTaskError(FailedTaskError::WasmModuleCreationError { code: "deserialization into WASM module".to_string(), err: err.to_string() })
    }
}

impl From<parity_wasm::elements::Module> for EnclaveError {
    fn from(err: parity_wasm::elements::Module) -> EnclaveError {
        EnclaveError::FailedTaskError(FailedTaskError::WasmModuleCreationError { code: "injecting gas counter".to_string(), err: format!("{:?}", err) })
    }
}

impl From<wasm_utils::stack_height::Error> for EnclaveError {
    fn from(err: wasm_utils::stack_height::Error) -> EnclaveError {
        EnclaveError::FailedTaskError(FailedTaskError::WasmModuleCreationError { code: "injecting stack height limiter".to_string(), err: format!("{:?}", err) })
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
                            WasmError::GasLimit => EnclaveError::FailedTaskError(FailedTaskError::GasLimitError),
                            WasmError::WasmiError(e) => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError { err: format!("{}", e) }),
                            WasmError::EnclaveError(err) => err.clone(),
                        }
                    },
                    TrapKind::Unreachable => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "unreachable".to_string() }),
                    TrapKind::MemoryAccessOutOfBounds => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "memory access out of bounds".to_string() }),
                    TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "table access out of bounds".to_string() }),
                    TrapKind::DivisionByZero => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "division by zero".to_string() }),
                    TrapKind::InvalidConversionToInt => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "invalid conversion to int".to_string() }),
                    TrapKind::UnexpectedSignature => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "unexpected signature".to_string() }),
                    TrapKind::StackOverflow => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError{ err: "stack overflow".to_string() }),
                }
            }
            _ => EnclaveError::FailedTaskError(FailedTaskError::WasmCodeExecutionError { err: e.to_string() })
        }
    }
}

#[derive(Debug, Clone)]
pub enum EnclaveError {
    FailedTaskError(FailedTaskError),
    FailedTaskErrorWithGas {
        used_gas: u64,
        err: FailedTaskError
    },
    SystemError(EnclaveSystemError)
}

impl ::std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match self {
            EnclaveError::FailedTaskError(ref e) => write!(f, "{}", e),
            EnclaveError::FailedTaskErrorWithGas{err, ..} => write!(f, "{}", err),
            EnclaveError::SystemError(ref e) => write!(f, "{}", e),
        }
    }
}

#[derive(Debug, Fail, Clone)]
pub enum FailedTaskError {
    #[fail(display = "Input Error: {}", message)]
    InputError { message: String },

    #[fail(display = "Error in execution of {}: {}", code, err)]
    WasmModuleCreationError { code: String, err: String },

    #[fail(display = "Error in execution of WASM code: {}", err)]
    WasmCodeExecutionError { err: String},

    #[fail(display = "Invocation resulted in gas limit violated")]
    GasLimitError,

    #[fail(display = "Error in EVM:  {}", err)]
    EvmError { err: String },
}

#[derive(Debug, Fail, Clone)]
pub enum EnclaveSystemError {
    #[fail(display = "Cryptography Error: {:?}", err)]
    CryptoError { err: CryptoError },

    #[fail(display = "There's no sufficient permissions to read this file: {}", file)]
    PermissionError { file: String },

    #[fail(display = "An SGX Error has occurred: {}, Description: {}", err, description)]
    SgxError { err: String, description: String },

    #[fail(display = "There's a State error with: {}", err)]
    StateError { err: String },

    #[fail(display = "There's an error with the ocall: {}; {}", command, err)]
    OcallError { command: String, err: String },

    #[fail(display = "There's an error with the messaging: {}", err)]
    MessagingError { err: String },

    #[fail(display = "Failed to authenticate the worker: {}", err)]
    WorkerAuthError { err: String },

    #[fail(display = "Failed to provide state key: {}", err)]
    KeyProvisionError { err: String },
}

impl From<CryptoError> for EnclaveError {
    fn from(err: CryptoError) -> EnclaveError {
        EnclaveError::SystemError(EnclaveSystemError::CryptoError { err })
    }
}

impl From<ToolsError> for EnclaveError {
    fn from(err: ToolsError) -> Self {
        match err {
            ToolsError::MessagingError {err} => EnclaveError::SystemError(EnclaveSystemError::MessagingError { err: err.to_string() })
        }
    }
}

impl From<sgx_status_t> for EnclaveError {
    fn from(err: sgx_status_t) -> EnclaveError {
        EnclaveError::SystemError(EnclaveSystemError::SgxError { err: err.as_str().to_string(), description: err.__description().to_string() })
    }
}

impl From<rmp_serde::decode::Error> for EnclaveError {
    fn from(err: rmp_serde::decode::Error) -> EnclaveError {
        EnclaveError::SystemError(EnclaveSystemError::StateError { err: format!("{:?}", err) })
    }
}

impl From<rmp_serde::encode::Error> for EnclaveError {
    fn from(err: rmp_serde::encode::Error) -> EnclaveError {
        EnclaveError::SystemError(EnclaveSystemError::StateError { err: format!("{:?}", err) })
    }
}

impl From<json_patch::PatchError> for EnclaveError {
    fn from(err: json_patch::PatchError) -> EnclaveError { EnclaveError::SystemError(EnclaveSystemError::StateError { err: format!("{}", err) } )}
}

impl From<str::Utf8Error> for EnclaveError {
    fn from(err: str::Utf8Error) -> Self { EnclaveError::FailedTaskError(FailedTaskError::InputError { message: format!("{:?}", err) } )}
}

impl From<hexutil::ParseHexError> for EnclaveError {
    fn from(err: hexutil::ParseHexError) -> Self { EnclaveError::FailedTaskError(FailedTaskError::InputError { message: format!("{:?}", err) } )}
}

impl ResultToEnclaveReturn for EnclaveError {
    fn into_enclave_return(self) -> EnclaveReturn { self.into() }
}

impl Into<EnclaveReturn> for EnclaveError {
    fn into(self) -> EnclaveReturn {
        use self::EnclaveError::*;
        match self {
            FailedTaskError {..} => EnclaveReturn::TaskFailure,
            FailedTaskErrorWithGas {..} => EnclaveReturn::TaskFailure,
            SystemError(e) => {
                use self::EnclaveSystemError::*;
                use self::CryptoError::*;
                match e {
                    PermissionError { .. } => EnclaveReturn::PermissionError,
                    SgxError { .. } => EnclaveReturn::SgxError,
                    StateError { .. } => EnclaveReturn::StateError,
                    OcallError { .. } => EnclaveReturn::OcallError,
                    MessagingError { .. } => EnclaveReturn::MessagingError,
                    CryptoError{err} => match err {
                        RandomError { .. } => EnclaveReturn::SgxError,
                        DerivingKeyError { .. } | KeyError { .. } | MissingKeyError { .. } => EnclaveReturn::KeysError,
                        DecryptionError { .. } | EncryptionError { .. } | SigningError { .. } | ImproperEncryption |
                        ParsingError { ..} | RecoveryError { .. } => EnclaveReturn::EncryptionError,
                    }
                    WorkerAuthError { .. } => EnclaveReturn::WorkerAuthError,
                    KeyProvisionError { .. } => EnclaveReturn::KeyProvisionError,
                 }

             }
        }
    }
}

