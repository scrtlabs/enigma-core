use core::{fmt, mem, ptr, default::Default};

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecuteResult {
    pub output: *const u8,
    pub delta_ptr: *const u8,
    pub delta_hash: [u8; 32],
    pub delta_index: u32,
    pub ethereum_payload_ptr: *const u8,
    pub ethereum_address: [u8; 20],
    pub signature: [u8; 65],
}

impl Default for ExecuteResult {
    fn default() -> ExecuteResult {
        ExecuteResult {
            output: ptr::null(),
            delta_ptr: ptr::null(),
            ethereum_payload_ptr: ptr::null(),
            .. unsafe { mem::zeroed() }
        }
    }
}

impl fmt::Debug for ExecuteResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_trait_builder = f.debug_struct("ExecuteResult");
        debug_trait_builder.field("output", &(self.output));
        debug_trait_builder.field("delta_ptr", &(self.delta_ptr));
        debug_trait_builder.field("delta_hash", &(self.delta_hash));
        debug_trait_builder.field("delta_index", &(self.delta_index));
        debug_trait_builder.field("ethereum_payload_ptr", &(self.ethereum_payload_ptr));
        debug_trait_builder.field("ethereum_address", &(self.ethereum_address));
        debug_trait_builder.field("signature", &(&self.signature[..]));
        debug_trait_builder.finish()
    }
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
            RecoveringError => "EnclaveReturn: RecoveringError",
            PermissionError => "EnclaveReturn: PermissionError",
            SgxError => "EnclaveReturn: SgxError",
            StateError => "EnclaveReturn: StateError",
            OcallError => "EnclaveReturn: OcallError",
            OcallDBError => "EnclaveReturn: OcallDBError",
            Utf8Error => "EnclaveReturn: Utf8Error",
            MessagingError => "EnclaveReturn: MessagingError",
            WorkerAuthError => "EnclaveReturn: WorkerAuthError",
            KeyProvisionError => "EnclaveReturn: KeyProvisionError",
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
            Err(e) => ResultToEnclaveReturn::into_enclave_return(e),
        }
    }
}
