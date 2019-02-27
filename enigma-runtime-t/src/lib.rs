#![no_std]
#![warn(unused_extern_crates)]


/// Enigma runtime implementation
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;
extern crate sgx_trts;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate enigma_tools_t;
extern crate enigma_crypto;
extern crate enigma_types;
extern crate json_patch;
extern crate rmp_serde as rmps;
#[macro_use]
extern crate serde;
extern crate wasmi;

use crate::data::{ContractState, DeltasInterface, IOInterface, StatePatch};
use enigma_tools_t::common::errors_t::{EnclaveError, WasmError};
use enigma_types::ContractAddress;
use std::{str, vec::Vec};
use std::string::{String, ToString};
use wasmi::{MemoryRef, RuntimeArgs, RuntimeValue};
use sgx_trts::trts::rsgx_read_rand;

pub mod data;
pub mod eng_resolver;
pub mod ocalls_t;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EthereumData{
    pub ethereum_payload: Vec<u8>,
    pub ethereum_contract_addr: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct RuntimeResult {
    pub state_delta: Option<StatePatch>,
    pub updated_state: ContractState,
    pub result: Vec<u8>,
    pub ethereum_bridge: Option<EthereumData>,
    pub used_gas: u64,
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
    pre_execution_state: ContractState,
    post_execution_state: ContractState,
}

type Result<T> = ::std::result::Result<T, WasmError>;

impl Runtime {
    pub fn new(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, contract_address: ContractAddress,
               function_name: String, args_types: String) -> Runtime {

        let init_state = ContractState::new(contract_address);
        let current_state = ContractState::new(contract_address);
        let result = RuntimeResult {
            result: Vec::new(),
            state_delta: None,
            updated_state: Default::default(),
            ethereum_bridge: Default::default(),
            used_gas: 0,
        };

        Runtime { gas_counter: 0, gas_limit, memory, function_name, args_types, args, result, pre_execution_state: init_state, post_execution_state: current_state }
    }

    pub fn new_with_state(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, state: ContractState,
                          function_name: String, args_types: String ) -> Runtime {
        let init_state = state.clone();
        let current_state = state;
        let result = RuntimeResult {
            result: Vec::new(),
            state_delta: None,
            updated_state: Default::default(),
            ethereum_bridge: Default::default(),
            used_gas: 0,
        };

        Runtime { gas_counter: 0, gas_limit, memory, function_name, args_types, args, result, pre_execution_state: init_state, post_execution_state: current_state }
    }

    fn fetch_args_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.args.len() as i32) }

    fn fetch_args(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        self.memory.set(ptr, &self.args)?;
        Ok(())
    }

    fn fetch_function_name_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.function_name.len() as i32) }

    fn fetch_function_name(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        self.memory.set(ptr, &self.function_name.as_bytes())?;
        Ok(())
    }

    fn fetch_types_length(&mut self) -> RuntimeValue { RuntimeValue::I32(self.args_types.len() as i32) }

    fn fetch_types(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;

        self.memory.set(ptr, &self.args_types.as_bytes())?;
        Ok(())
    }

    pub fn read_state_len (&mut self, args: RuntimeArgs) -> Result<i32> {
        // TODO: Handle the error here, should we return len=0?;
        let key = args.nth_checked(0)?;
        let key_len: u32 = args.nth_checked(1)?;
        let mut buf = vec![0u8; key_len as usize];
        self.memory.get_into(key, &mut buf[..])?;
        let key1 = str::from_utf8(&buf)?;
        let value_vec =
            serde_json::to_vec(&self.post_execution_state.json[key1]).expect("Failed converting Value to vec in Runtime while reading state");
        Ok( value_vec.len() as i32 )
    }


    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of key
    ///
    /// Read `key` from the memory, then read from the state the value under the `key`
    /// and copy it to the memory at address 0.
    pub fn read_state (&mut self, args: RuntimeArgs) -> Result<()> {
        // TODO: Handle the error here, should we return len=0?;
        let key = args.nth_checked(0)?;
        let key_len: u32 = args.nth_checked(1)?;
        let value_holder: u32 = args.nth_checked(2)?;

        let mut buf = vec![0u8; key_len as usize];
        self.memory.get_into(key, &mut buf[..])?;

        let key1 = str::from_utf8(&buf)?;
        let value_vec =
            serde_json::to_vec(&self.post_execution_state.json[key1]).expect("Failed converting Value to vec in Runtime while reading state");
        self.memory.set(value_holder, &value_vec)?;
        Ok(())
    }

    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of the key
    /// * `value` - the start address of value in memory
    /// * `value_len` - the length of the value
    ///
    /// Read `key` and `value` from memory, and write (key, value) pair to the state
    pub fn write_state (&mut self, args: RuntimeArgs) -> Result<()>{
        let key = args.nth_checked(0)?;
        let key_len: u32 = args.nth_checked(1)?;
        let value: u32 = args.nth_checked(2)?;
        let value_len: u32 = args.nth_checked(3)?;

        let mut buf = vec![0u8; key_len as usize];
        self.memory.get_into(key, &mut buf[..])?;

        let mut val = vec![0u8; value_len as usize];
        self.memory.get_into(value, &mut val[..])?;

        let key1 = str::from_utf8(&buf)?;
        let value: serde_json::Value =
            serde_json::from_slice(&val).expect("Failed converting into Value while writing state in Runtime");
        self.post_execution_state.write_key(key1, &value)?;
        Ok(())
    }

    /// args:
    /// * `payload` - the start address of key in memory
    /// * `payload_len` - the length of the key
    /// * `address` - the start address of key in memory
    ///
    /// Read `payload` and `address` from memory, and write it to result
    pub fn write_eth_bridge(&mut self, args: RuntimeArgs) -> Result<()> {
        let payload = args.nth_checked(0)?;
        let payload_len: u32 = args.nth_checked(1)?;
        let address = args.nth_checked(2)?;

        let mut bridge = EthereumData{ethereum_payload: vec![0u8; payload_len as usize], ethereum_contract_addr: Default::default()};

        self.memory.get_into(payload, &mut bridge.ethereum_payload[..])?;
        self.memory.get_into(address, &mut bridge.ethereum_contract_addr[..])?;
        self.result.ethereum_bridge = Some(bridge);
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

        self.result.result = self.memory.get(ptr, len as usize)?;
        Ok(())
    }

    pub fn rand(&mut self, args: RuntimeArgs) -> Result<()> {
        let ptr: u32 = args.nth_checked(0)?;
        let len: u32 = args.nth_checked(1)?;

        let mut buf = vec![0u8; len as usize];
        match rsgx_read_rand(&mut buf[..]) {
            Ok(_) => {
                self.memory.set(ptr, &buf[..])?;
                Ok(())
            },
            Err(e) => Err(WasmError::EngRuntime(format!("{}", e))),
        }
    }

    /// Destroy the runtime, returning currently recorded result of the execution
    pub fn into_result(mut self) -> ::std::result::Result<RuntimeResult, EnclaveError> {
        self.result.state_delta = {
            // The delta is always generated after a deployment.
            // The delta is generated after an execution only if there is a state change.
            if (&self.pre_execution_state != &self.post_execution_state) || (self.pre_execution_state.is_initial()){
                Some(ContractState::generate_delta_and_update_state(&self.pre_execution_state, &mut self.post_execution_state)?)
            } else{
                None
            }
        };
        self.result.used_gas = self.gas_counter;
        self.result.updated_state = self.post_execution_state;
        Ok(self.result.clone())
    }

    pub fn eprint(&mut self, args: RuntimeArgs) -> Result<()> {
        let msg_ptr: u32 = args.nth_checked(0)?;
        let msg_len: u32 = args.nth_checked(1)?;
        let res = self.memory.get(msg_ptr, msg_len as usize)?;
        let st = str::from_utf8(&res)?;
        debugln!("PRINT: {}", st);
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
                eng_resolver::ids::READ_STATE_LEN_FUNC => {
                    let res = Runtime::read_state_len(self, args)?;
                    Ok(Some(RuntimeValue::I32(res)))
                }
                eng_resolver::ids::READ_STATE_FUNC => {
                    Runtime::read_state(self, args)?;
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

                eng_resolver::ids::WRITE_ETH_BRIDGE_FUNC => {
                    Runtime::write_eth_bridge(self, args)?;
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
