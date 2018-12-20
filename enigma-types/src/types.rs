
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
    Utf8Error,
    MessagingError,
    WorkerAuthError,
    KeyProvisionError,
    Other
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
