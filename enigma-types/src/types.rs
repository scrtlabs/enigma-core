use core::default::Default;
use core::fmt;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    Success,
    WasmError,
    EVMError,
    KeysError,
    EncryptionError,
    InputError,
    SigningError,
    RecoveringError,
    PermissionError,
    SgxError,
    StateError,
    OcallError,
    OcallDBError,
    Utf8Error,
    MessagingError,
    WorkerAuthError,
    KeyProvisionError,
    Other
}

impl Default for EnclaveReturn {
    fn default() -> EnclaveReturn { EnclaveReturn::Success }
}

impl fmt::Display for EnclaveReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EnclaveReturn::*;
        let p = match *self {
            Success => "EnclaveReturn: Success",
            WasmError => "EnclaveReturn: WasmError",
            EVMError => "EnclaveReturn: EVMError",
            KeysError => "EnclaveReturn: KeysError",
            EncryptionError => "EnclaveReturn: EncryptionError",
            InputError => "EnclaveReturn: InputError",
            SigningError => "EnclaveReturn: SigningError",
            PermissionError => "EnclaveReturn: PermissionError",
            SgxError => "EnclaveReturn: SgxError",
            StateError => "EnclaveReturn: StateError",
            OcallError => "EnclaveReturn: OcallError",
            OcallDBError => "EnclaveReturn: OcallDBError",
            Utf8Error => "EnclaveReturn: Utf8Error",
            MessagingError => "EnclaveReturn: MessagingError",
            Other => "EnclaveReturn: Other",
        };
        write!(f, "{}", p)
    }
}

pub trait ResultToEnclaveReturn {
    fn into_enclave_return(self) -> EnclaveReturn;
}

impl<T: ResultToEnclaveReturn> From<Result<(), T>> for EnclaveReturn {
    fn from(res: Result<(), T>) -> Self {
        match res {
            Ok(()) => EnclaveReturn::Success,
            Err(e) => ResultToEnclaveReturn::into_enclave_return(e)
        }
    }
}
