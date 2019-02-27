use core::{fmt, mem, ptr, default::Default};

pub use crate::hash::Hash256;
pub type SymmetricKey = [u8; 32];
pub type StateKey = SymmetricKey;
pub type DhKey = SymmetricKey;
pub type ContractAddress = Hash256;
pub type PubKey = [u8; 64];

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    Success,
    WasmCodeExecutionError,
    GasLimitError,
    WasmModuleError,
    EVMError,
    KeysError,
    EncryptionError,
    InputError,
    SigningError,
    PermissionError,
    SgxError,
    StateError,
    OcallError,
    OcallDBError,
    MessagingError,
    Other,
//    Uninitialized,
}


#[derive(Debug)]
pub enum ResultStatus {
    Success,
    Failure,
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecuteResult {
    pub output: *const u8,
    pub delta_ptr: *const u8,
    pub delta_index: u32,
    pub ethereum_payload_ptr: *const u8,
    pub ethereum_address: [u8; 20],
    pub signature: [u8; 65],
    pub used_gas: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawPointer {
    ptr: *const u8,
    _mut: bool
}

impl RawPointer {
    pub unsafe fn new<T>(reference: &T) -> Self {
        RawPointer { ptr: reference as *const T as *const u8, _mut: false }
    }

    pub unsafe fn new_mut<T>(reference: &mut T) -> Self {
        RawPointer { ptr: reference as *mut T as *const u8, _mut: true }
    }

    pub fn get_ptr<T>(&self) -> *const T {
        self.ptr as *const T
    }

    pub fn get_mut_ptr<T>(&self) -> Result<*mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(self.ptr as *mut T)
        }
    }

    pub unsafe fn get_ref<T>(&self) ->  &T {
        &*(self.ptr as *const T)
    }

    pub unsafe fn get_mut_ref<T>(&self) -> Result<&mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(&mut *(self.ptr as *mut T) )
        }
    }


}



impl From<ResultStatus> for u8 {
    fn from(i: ResultStatus) -> Self {
        match i{
            ResultStatus::Success => 1u8,
            ResultStatus::Failure => 0u8,
        }
    }
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
        debug_trait_builder.field("delta_index", &(self.delta_index));
        debug_trait_builder.field("ethereum_payload_ptr", &(self.ethereum_payload_ptr));
        debug_trait_builder.field("ethereum_address", &(self.ethereum_address));
        debug_trait_builder.field("signature", &(&self.signature[..]));
        debug_trait_builder.field("used_gas", &(self.used_gas));
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
            WasmCodeExecutionError => "EnclaveReturn: WasmCodeExecutionError",
            GasLimitError => "EnclaveReturn: GasLimitError",
            WasmModuleError => "EnclaveReturn: WasmModuleError",
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
            Err(e) => ResultToEnclaveReturn::into_enclave_return(e),
        }
    }
}
