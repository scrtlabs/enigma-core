extern crate wasmi;

use wasmi::{MemoryRef, RuntimeArgs, RuntimeValue, Error as InterpreterError, Trap, TrapKind, Externals};
use std::vec::Vec;
use std::string::String;
use wasm_g::eng_resolver;

/// User trap in native code
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Storage read error
    StorageReadError,
    /// Storage update error
    StorageUpdateError,
    /// Memory access violation
    MemoryAccessViolation,
    /// Native code resulted in suicide
    Suicide,
    /// Native code requested execution to finish
    Return,
    /// Suicide was requested but coudn't complete
    SuicideAbort,
    /// Invalid gas state inside interpreter
    InvalidGasState,
    /// Query of the balance resulted in an error
    BalanceQueryError,
    /// Failed allocation
    AllocationFailed,
    /// Gas limit reached
    GasLimit,
    /// Unknown runtime function
    Unknown,
    /// Passed string had invalid utf-8 encoding
    BadUtf8,
    /// Log event error
    Log,
    /// Other error in native code
    Other,
    /// Syscall signature mismatch
    InvalidSyscall,
    /// Unreachable instruction encountered
    Unreachable,
    /// Invalid virtual call
    InvalidVirtualCall,
    /// Division by zero
    DivisionByZero,
    /// Invalid conversion to integer
    InvalidConversionToInt,
    /// Stack overflow
    StackOverflow,
    /// Panic with message
    Panic(String),
}

impl From<Trap> for Error {
    fn from(trap: Trap) -> Self {
        match *trap.kind() {
            TrapKind::Unreachable => Error::Unreachable,
            TrapKind::MemoryAccessOutOfBounds => Error::MemoryAccessViolation,
            TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => Error::InvalidVirtualCall,
            TrapKind::DivisionByZero => Error::DivisionByZero,
            TrapKind::InvalidConversionToInt => Error::InvalidConversionToInt,
            TrapKind::UnexpectedSignature => Error::InvalidVirtualCall,
            TrapKind::StackOverflow => Error::StackOverflow,
        }
    }
}

impl wasmi::HostError for Error { }

impl From<InterpreterError> for Error {
    fn from(err: InterpreterError) -> Self {
        match err {
            InterpreterError::Value(_) => Error::InvalidSyscall,
            InterpreterError::Memory(_) => Error::MemoryAccessViolation,
            _ => Error::Other,
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match *self {
            Error::StorageReadError => write!(f, "Storage read error"),
            Error::StorageUpdateError => write!(f, "Storage update error"),
            Error::MemoryAccessViolation => write!(f, "Memory access violation"),
            Error::SuicideAbort => write!(f, "Attempt to suicide resulted in an error"),
            Error::InvalidGasState => write!(f, "Invalid gas state"),
            Error::BalanceQueryError => write!(f, "Balance query resulted in an error"),
            Error::Suicide => write!(f, "Suicide result"),
            Error::Return => write!(f, "Return result"),
            Error::Unknown => write!(f, "Unknown runtime function invoked"),
            Error::AllocationFailed => write!(f, "Memory allocation failed (OOM)"),
            Error::BadUtf8 => write!(f, "String encoding is bad utf-8 sequence"),
            Error::GasLimit => write!(f, "Invocation resulted in gas limit violated"),
            Error::Log => write!(f, "Error occured while logging an event"),
            Error::InvalidSyscall => write!(f, "Invalid syscall signature encountered at runtime"),
            Error::Other => write!(f, "Other unspecified error"),
            Error::Unreachable => write!(f, "Unreachable instruction encountered"),
            Error::InvalidVirtualCall => write!(f, "Invalid virtual call"),
            Error::DivisionByZero => write!(f, "Division by zero"),
            Error::StackOverflow => write!(f, "Stack overflow"),
            Error::InvalidConversionToInt => write!(f, "Invalid conversion to integer"),
            Error::Panic(ref msg) => write!(f, "Panic: {}", msg),
        }
    }
}


//pub struct Runtime<'a> {
pub struct Runtime {
    memory: MemoryRef,
    args: Vec<u8>,
    result: Vec<u8>,
}

//impl<'a> Runtime<'a> {
impl Runtime {

    pub fn new(memory: MemoryRef, args: Vec<u8>,) -> Runtime {
        Runtime {
            memory: memory,
            args: args,
            result: Vec::new(),
        }
    }

    pub fn moria() -> Result<i32, Error>
    {
        Ok(200)
    }

    /// Sets a return value for the call
    ///
    /// Syscall takes 2 arguments:
    /// * pointer in sandboxed memory where result is
    /// * the length of the result
    pub fn ret(&mut self, args: RuntimeArgs) -> Result<(), Error> {
        let ptr: u32 = args.nth_checked(0)?;
        let len: u32 = args.nth_checked(1)?;

        self.result = self.memory.get(ptr, len as usize)?;

        Err(Error::Return)
    }

    /// Destroy the runtime, returning currently recorded result of the execution
    pub fn into_result(self) -> Vec<u8> {
        self.result
    }

}



//impl<'a> Externals for Runtime<'a> {
impl Externals for Runtime {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            eng_resolver::ids::EXTERNAL_FUNC => {
                Ok(Some(RuntimeValue::I32(Runtime::moria().unwrap())))
            }
            eng_resolver::ids::RET_FUNC => {
                &mut Runtime::ret(self, args);
                Ok(None)
            }
            _ => panic!("Unimplemented function at {}", index),
        }
    }
}

