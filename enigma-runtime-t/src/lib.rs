#![no_std]

/// Enigma runtime implementation
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;
extern crate sgx_trts;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate enigma_tools_t;
extern crate enigma_types;
extern crate hexutil;
extern crate json_patch;
extern crate rmp_serde as rmps;
extern crate serde;
extern crate wasmi;

use crate::data::{ContractState, DeltasInterface, IOInterface, StatePatch};
use enigma_tools_t::common::errors_t::EnclaveError;
use std::{str, vec::Vec};
use std::string::{String, ToString};
use wasmi::{Externals, MemoryRef, RuntimeArgs, RuntimeValue, Trap, TrapKind};
use sgx_trts::trts::rsgx_read_rand;

pub mod data;
pub mod eng_resolver;
pub mod ocalls_t;

#[derive(Debug, Clone)]
pub struct RuntimeResult {
    pub state_delta: Option<StatePatch>,
    pub updated_state: Option<ContractState>,
    pub result: Vec<u8>,
    pub ethereum_payload: Vec<u8>,
    pub ethereum_contract_addr: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct Runtime {
    gas_counter: u64,
    gas_limit: u64,
    memory: MemoryRef,
    function_name: String,
    args_types: String,
    args: Vec<u8>,
    result: RuntimeResult,
    init_state: ContractState,
    current_state: ContractState,
}

#[derive(Debug)]
pub enum WasmError {
    GasLimit,
    Memory(String),
    Delta(String),
    Other,
}

impl wasmi::HostError for WasmError {}

type Result<T> = ::std::result::Result<T, WasmError>;

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match *self {
            WasmError::GasLimit => write!(f, "Invocation resulted in gas limit violated"),
            WasmError::Memory(ref s) => write!(f, "{}", s),
            WasmError::Delta(ref s) => write!(f, "{}", s),
            WasmError::Other => write!(f, "Other"),
        }
    }
}

impl From<wasmi::Trap> for WasmError {
    fn from(trap: wasmi::Trap) -> Self { WasmError::Other }
}

impl From<WasmError> for EnclaveError {
    fn from(e: WasmError) -> Self { EnclaveError::ExecutionError { code: "".to_string(), err: "from E to Enclave".to_string() } }
}
impl From<str::Utf8Error> for WasmError {
    fn from(err: str::Utf8Error) -> Self { WasmError::Other }
}

impl Runtime {
    pub fn new(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, contract_id: [u8; 32],
               function_name: String, args_types: String) -> Runtime {

        let init_state = ContractState::new(contract_id);
        let current_state = ContractState::new(contract_id);
        let result = RuntimeResult {
            result: Vec::new(),
            state_delta: None,
            updated_state: None,
            ethereum_payload: Vec::new(),
            ethereum_contract_addr: [0u8; 20],
        };

        Runtime { gas_counter: 0, gas_limit, memory, function_name, args_types, args, result, init_state, current_state }
    }

    pub fn new_with_state(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, state: ContractState,
                          function_name: String, args_types: String ) -> Runtime {
        let init_state = state.clone();
        let current_state = state;
        let result = RuntimeResult {
            result: Vec::new(),
            state_delta: None,
            updated_state: None,
            ethereum_payload: Vec::new(),
            ethereum_contract_addr: [0u8; 20],
        };

        Runtime { gas_counter: 0, gas_limit, memory, function_name, args_types, args, result, init_state, current_state }
    }

    fn fetch_args_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.args.len() as i32) }

    fn fetch_args(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        match self.memory.set(ptr, &self.args) {
            Ok(_v) => Ok(()),
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
    }

    fn fetch_function_name_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.function_name.len() as i32) }

    fn fetch_function_name(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        match self.memory.set(ptr, &self.function_name.as_bytes()) {
            Ok(_v) => Ok(()),
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
    }

    fn fetch_types_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.args_types.len() as i32) }

    fn fetch_types(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        match self.memory.set(ptr, &self.args_types.as_bytes()) {
            Ok(_v) => Ok(()),
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
    }
    /// args:
    /// * `value` - value holder: the start address of value in memory
    /// * `value_len` - the length of value holder
    ///
    /// Copy memory starting address 0 of length 'value_len' to `value` and to `self.result.result`
    pub fn from_memory(&mut self, args: RuntimeArgs) -> Result<()> {
        let value: u32 = args.nth_checked(0).unwrap();
        let value_len: i32 = args.nth_checked(1).unwrap();

        let mut buf = Vec::with_capacity(value_len as usize);
        for _ in 0..value_len {
            buf.push(0);
        }

        match self.memory.get_into(0, &mut buf[..]) {
            Ok(()) => {
                match self.memory.set(value, &buf[..]) {
                    Ok(()) => {
                        self.result.result = match self.memory.get(0, value_len as usize) {
                            Ok(v) => v,
                            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
                        };
                    }
                    Err(e) => return Err(WasmError::Memory(format!("{}", e))),
                }
                Ok(())
            }
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
    }

    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of key
    ///
    /// Read `key` from the memory, then read from the state the value under the `key`
    /// and copy it to the memory at address 0.
    pub fn read_state (&mut self, args: RuntimeArgs) -> Result<i32> {
        // TODO: Handle the error here, should we return len=0?;
        let key = args.nth_checked(0);
        let key_len: u32 = args.nth_checked(1).unwrap();
        let mut buf = Vec::with_capacity(key_len as usize);
        for _ in 0..key_len {
            buf.push(0);
        }
        match self.memory.get_into(key.unwrap(), &mut buf[..]) {
            Ok(()) => (),
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
        let key1 = str::from_utf8(&buf)?;
        let value_vec =
            serde_json::to_vec(&self.current_state.json[key1]).expect("Failed converting Value to vec in Runtime while reading state");
        self.memory.set(0, &value_vec).unwrap(); // TODO: Impl From so we could use `?`
        Ok( value_vec.len() as i32 )
    }

    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of the key
    /// * `value` - the start address of value in memory
    /// * `value_len` - the length of the value
    ///
    /// Read `key` and `value` from memory, and write (key, value) pair to the state
    pub fn write_state (&mut self, args: RuntimeArgs) -> Result<()>{
        let key = args.nth_checked(0);
        let key_len: u32 = args.nth_checked(1).unwrap();
        let value: u32 = args.nth_checked(2).unwrap();
        let value_len: u32 = args.nth_checked(3).unwrap();

        let mut buf = Vec::with_capacity(key_len as usize);
        for _ in 0..key_len {
            buf.push(0);
        }

        match self.memory.get_into(key.unwrap(), &mut buf[..]) {
            Ok(v) => v,
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }

        let mut val = Vec::with_capacity(value_len as usize);
        for _ in 0..value_len {
            val.push(0);
        }

        match self.memory.get_into(value, &mut val[..]) {
            Ok(v) => v,
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }

        let key1 = str::from_utf8(&buf)?;
        let value: serde_json::Value =
            serde_json::from_slice(&val).expect("Failed converting into Value while writing state in Runtime");
        self.current_state.write_key(key1, &value).unwrap();
        Ok(())
    }

    /// args:
    /// * `payload` - the start address of key in memory
    /// * `payload_len` - the length of the key
    ///
    /// Read `payload` from memory, and write it to result
    pub fn write_payload(&mut self, args: RuntimeArgs) -> Result<()> {
        let payload = args.nth_checked(0)?;
        let payload_len: u32 = args.nth_checked(1)?;

        self.result.ethereum_payload = Vec::with_capacity(payload_len as usize);
        for _ in 0..payload_len {
            self.result.ethereum_payload.push(0);
        }

        match self.memory.get_into(payload, &mut self.result.ethereum_payload[..]) {
            Ok(v) => v,
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }

        Ok(())
    }

    /// args:
    /// * `address` - the start address of key in memory
    ///
    /// Read `address` from memory, and write it to result
    pub fn write_address(&mut self, args: RuntimeArgs) -> Result<()> {
        let address = args.nth_checked(0)?;

        match self.memory.get_into(address, &mut self.result.ethereum_contract_addr[..]) {
            Ok(v) => v,
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }

        Ok(())
    }

    /// args:
    /// * `ptr` - the start address in memory
    /// * `len` - the length
    ///
    /// Copy the memory of length `len` starting at address `ptr` to `self.result.result`
    pub fn ret(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;
        let len: u32 = args.nth_checked(1)?;

        self.result.result = match self.memory.get(ptr, len as usize) {
            Ok(v) => v,
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        };
        Ok(())
    }

    pub fn rand(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;
        let len: u32 = args.nth_checked(1)?;

        let mut buf = Vec::with_capacity(len as usize);
        for _ in 0..len {
            buf.push(0);
        }

        match rsgx_read_rand(&mut buf[..]) {
            Ok(_) => {
                match self.memory.set(ptr, &buf[..]) {
                    Ok(_) => Ok(()),
                    Err(e) => return Err(WasmError::Memory(format!("{}", e))),
                }
            },
            Err(_) => Err(WasmError::Other),
        }
    }

    /// Destroy the runtime, returning currently recorded result of the execution
    pub fn into_result(mut self) -> Result<RuntimeResult> {
        self.result.state_delta = match ContractState::generate_delta(&self.init_state, &self.current_state) {
            Ok(v) => Some(v),
            Err(e) => return Err(WasmError::Delta(format!("{}", e))),
        };

        self.result.updated_state = Some(self.current_state);
        Ok(self.result.clone())
    }

    pub fn eprint(&mut self, args: RuntimeArgs) -> Result<()> {
        let msg_ptr: u32 = args.nth_checked(0)?;
        let msg_len: u32 = args.nth_checked(1)?;
        match self.memory.get(msg_ptr, msg_len as usize) {
            Ok(res) => {
                let st = str::from_utf8(&res)?;
                println!("PRINT: {}", st);
            }
            Err(e) => return Err(WasmError::Memory(format!("{}", e))),
        }
        Ok(())
    }

    pub fn gas(&mut self, args: RuntimeArgs) -> Result<()> {
        let amount: u32 = args.nth_checked(0)?;
        if self.charge_gas(amount as u64) {
            Ok(())
        } else {
            Err(WasmError::GasLimit)
        }
    }

    fn charge_gas(&mut self, amount: u64) -> bool {
        let prev = self.gas_counter;
        match prev.checked_add(amount) {
            None => false,
            Some(val) if val > self.gas_limit => false,
            Some(_) => {
                self.gas_counter = prev + amount;
                true
            }
        }
    }
}

mod ext_impl {
    use super::{eng_resolver, Runtime};
    use wasmi::{Externals, RuntimeArgs, RuntimeValue, Trap};
    impl Externals for Runtime {
        fn invoke_index(&mut self, index: usize, args: RuntimeArgs) -> Result<Option<RuntimeValue>, Trap> {
            match index {
                eng_resolver::ids::RET_FUNC => {
                    Runtime::ret(self, args)?;
                    Ok(None)
                }
                eng_resolver::ids::WRITE_STATE_FUNC => {
                    Runtime::write_state(self, args)?;
                    Ok(None)
                }
                eng_resolver::ids::READ_STATE_FUNC => {
                    let res = Runtime::read_state(self, args)?;
                    Ok(Some(RuntimeValue::I32(res)))
                }
                eng_resolver::ids::FROM_MEM_FUNC => {
                    Runtime::from_memory(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::EPRINT_FUNC => {
                    Runtime::eprint(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::NAME_LENGTH_FUNC => Ok(Some(Runtime::fetch_function_name_length(self))),

                eng_resolver::ids::NAME_FUNC => {
                    Runtime::fetch_function_name(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::ARGS_LENGTH_FUNC => Ok(Some(Runtime::fetch_args_length(self))),

                eng_resolver::ids::ARGS_FUNC => {
                    Runtime::fetch_args(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::TYPES_LENGTH_FUNC => Ok(Some(Runtime::fetch_types_length(self))),

                eng_resolver::ids::TYPES_FUNC => {
                    Runtime::fetch_types(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::WRITE_PAYLOAD_FUNC => {
                    Runtime::write_payload(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::WRITE_ADDRESS_FUNC => {
                    Runtime::write_address(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::GAS_FUNC => {
                    Runtime::gas(self, args)?;
                    Ok(None)
                }

                eng_resolver::ids::RAND_FUNC => {
                    Runtime::rand(self, args)?;
                    Ok(None)
                }

                _ => unimplemented!("Unimplemented function at {}", index),
            }
        }
    }
}
