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
extern crate serde;
extern crate wasmi;

use crate::data::{ContractState, DeltasInterface, IOInterface, EncryptedPatch};
use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, EnclaveSystemError::*, WasmError, EnclaveSystemError};
use enigma_types::{ContractAddress, StateKey, SymmetricKey};
use std::{str, vec::Vec};
use std::string::{String, ToString};
use wasmi::{MemoryRef, RuntimeArgs, RuntimeValue};
use sgx_trts::trts::rsgx_read_rand;
use enigma_crypto::symmetric::{IV, encrypt_with_nonce, decrypt, SYMMETRIC_KEY_SIZE, IV_SIZE};

pub mod data;
pub mod eng_resolver;
pub mod ocalls_t;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EthereumData {
    pub ethereum_payload: Vec<u8>,
    pub ethereum_contract_addr: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct RuntimeResult {
    pub state_delta: Option<EncryptedPatch>,
    pub updated_state: ContractState,
    pub result: Vec<u8>,
    pub ethereum_bridge: Option<EthereumData>,
    pub used_gas: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeWasmCosts {
    write_value: u64,
    write_additional_byte: u64,
    deploy_byte: u64,
    execution: u64,
}

impl Default for RuntimeWasmCosts {
    fn default() -> Self {
        RuntimeWasmCosts {
            write_value: 10,
            write_additional_byte: 1,
            deploy_byte: 1,
            execution: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Runtime {
    gas_counter: u64,
    gas_limit: u64,
    gas_return: u64,
    memory: MemoryRef,
    function_name: String,
    args_types: String,
    args: Vec<u8>,
    result: RuntimeResult,
    pre_execution_state: ContractState,
    post_execution_state: ContractState,
    key: StateKey,
    gas_costs: RuntimeWasmCosts,
}

type Result<T> = ::std::result::Result<T, WasmError>;

impl Runtime {
    pub fn new(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, contract_address: ContractAddress,
               function_name: String, args_types: String, key: StateKey) -> Runtime {
        let state = ContractState::new(contract_address);
        Self::new_with_state(gas_limit, memory, args, state, function_name, args_types, key, RuntimeWasmCosts::default())
    }

    pub fn new_with_state(gas_limit: u64, memory: MemoryRef, args: Vec<u8>, state: ContractState,
                          function_name: String, args_types: String, key: StateKey, costs: RuntimeWasmCosts) -> Runtime {
        let pre_execution_state = state.clone();
        let post_execution_state = state;
        let result = RuntimeResult {
            result: Vec::new(),
            state_delta: None,
            updated_state: Default::default(),
            ethereum_bridge: Default::default(),
            used_gas: 0,
        };
        Runtime { gas_counter: 0, gas_limit, gas_return: 0, memory, function_name, args_types, args, result, pre_execution_state, post_execution_state, key, gas_costs: costs }
    }

    pub fn get_used_gas(&self) -> u64 {
        self.gas_counter
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

    fn read_state_key_from_memory(&self, args: &RuntimeArgs, arg_index: usize, arg_len_index: usize) -> Result<String> {
        let key = args.nth_checked(arg_index)?;
        let key_len: u32 = args.nth_checked(arg_len_index)?;
        let mut buf = vec![0u8; key_len as usize];
        self.memory.get_into(key, &mut buf[..])?;

        // This should not fail if read/write from/to state is done properly through eng_wasm read!/write!
        let key_str = str::from_utf8(&buf).unwrap_or_default();
        Ok(key_str.to_string())
    }

    pub fn read_state_len(&self, args: RuntimeArgs) -> Result<i32> {
        // TODO: Handle the error here, should we return len=0?;
        let key = self.read_state_key_from_memory(&args, 0, 1)?;
        let value_vec =
            serde_json::to_vec(&self.post_execution_state.json[&key]).
                expect("Failed converting Value to vec in Runtime while reading state");
        Ok(value_vec.len() as i32)
    }


    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of key
    ///
    /// Read `key` from the memory, then read from the state the value under the `key`
    /// and copy it to `value_holder`.
    pub fn read_state(&mut self, args: RuntimeArgs) -> Result<()> {
        // TODO: Handle the error here, should we return len=0?;
        let key = self.read_state_key_from_memory(&args, 0, 1)?;
        let value_holder: u32 = args.nth_checked(2)?;

        let value_vec =
            serde_json::to_vec(&self.post_execution_state.json[key]).expect("Failed converting Value to vec in Runtime while reading state");
        self.memory.set(value_holder, &value_vec)?;
        Ok(())
    }

    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of key
    ///
    /// Read `key` from the memory, then remove the `key` from the state
    pub fn remove_from_state(&mut self, args: RuntimeArgs) -> Result<()> {
        let key = self.read_state_key_from_memory(&args, 0, 1)?;

        self.post_execution_state.remove_key(&key);
        Ok(())
    }

    /// args:
    /// * `key` - the start address of key in memory
    /// * `key_len` - the length of the key
    /// * `value` - the start address of value in memory
    /// * `value_len` - the length of the value
    ///
    /// Read `key` and `value` from memory, and write (key, value) pair to the state
    /// the cost of writing into the state is calculated by `calculate_gas_for_writing`
    pub fn write_state(&mut self, args: RuntimeArgs) -> Result<()> {
        let key = self.read_state_key_from_memory(&args, 0, 1)?;
        let value: u32 = args.nth_checked(2)?;
        let value_len: u32 = args.nth_checked(3)?;

        let mut val = vec![0u8; value_len as usize];
        let gas_amount = self.calculate_gas_for_writing(value_len as u64, &key)?;
        self.charge_gas(gas_amount)?;
        self.memory.get_into(value, &mut val[..])?;

        let value: serde_json::Value =
            serde_json::from_slice(&val).expect("Failed converting into Value while writing state in Runtime");
        self.post_execution_state.write_key(&key, &value)?;
        Ok(())
    }

    fn treat_gas_overflow(&mut self, val: &Option<u64>) -> Result<()> {
        if val.is_none() {
            self.gas_counter = self.gas_limit;
            Err(WasmError::GasLimit)
        } else {
            Ok(())
        }
    }

    fn treat_gas_underflow(&mut self, val: &Option<u64>) -> (bool, u64) {
        let result = 0;
        if let Some(v) = val {
            (false, *v)
        } else {
            self.gas_return = self.gas_limit;
            (true, result)
        }
    }

    /// args:
   /// * `new_value_len` - the length of of the new value to be written under the `key`
   /// * `key` - the key to write the new value
   /// calculate the gas to be charged for the writing of the new value.
   /// There is an initial constant value charged for the writing
   /// If the new value is larger than the old one, then gas is charged for the new bytes.
   /// If the new value is smaller than the old one, then the gas is returned for the removed bytes.
    fn calculate_gas_for_writing(&mut self, new_value_len: u64, key: &str) -> Result<u64> {
        let mut result = Some(0);
        let val = self.post_execution_state.json[key].clone();
        let mut old_value_len = 0;
        // forcing the length of Null value to be 0, since it is not 0.
        if !val.is_null() {
            let old_value_vec =
                serde_json::to_vec(&val).expect("Failed converting Value to vec in Runtime while reading state");
            old_value_len = old_value_vec.len() as u64;
        }
        // If the new value is larger than the old one, the gas should be charged
        if new_value_len >= old_value_len {
            let checked_val = (new_value_len - old_value_len).checked_mul(self.gas_costs.write_additional_byte);
            self.treat_gas_overflow(&checked_val)?;
            result = self.gas_costs.write_value.checked_add(checked_val.unwrap());
            self.treat_gas_overflow(&result)?;
        } // If the new value is smaller than the old one, the gas should be returned
        else {
            let decrease_cost = (old_value_len - new_value_len).checked_mul(self.gas_costs.write_additional_byte);
            let (underflow, _val) = self.treat_gas_underflow(&decrease_cost);
            if !underflow {
                let tmp = self.gas_return.checked_add(decrease_cost.unwrap());
                let (underflow, val) = self.treat_gas_underflow(&tmp);
                if !underflow {
                    self.gas_return = val;
                }
            }
        }
        Ok(result.unwrap())
    }

    /// args:
    /// * `payload` - the start address of payload in memory
    /// * `payload_len` - the length of the payload
    /// * `address` - the start address of address in memory
    ///
    /// Read `payload` and `address` from memory, and write it to result
    pub fn write_eth_bridge(&mut self, args: RuntimeArgs) -> Result<()> {
        let payload = args.nth_checked(0)?;
        let payload_len: u32 = args.nth_checked(1)?;
        let address = args.nth_checked(2)?;

        let mut bridge = EthereumData { ethereum_payload: vec![0u8; payload_len as usize], ethereum_contract_addr: Default::default() };

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
            }
            Err(e) => Err(SystemError(SgxError { err: format!("{}", e), description: e.__description().to_string() }))?
        }
    }

    /// Destroy the runtime, returning currently recorded result of the execution
    pub fn into_result(mut self) -> ::std::result::Result<RuntimeResult, EnclaveError> {
        if self.gas_counter >= self.gas_return {
            self.result.used_gas = self.gas_counter - self.gas_return;
        } else {
            self.result.used_gas = 0;
        }
        self.result.state_delta = {
            // The delta is always generated after a deployment.
            // The delta is generated after an execution only if there is a state change.
            if (&self.pre_execution_state != &self.post_execution_state) || (self.pre_execution_state.is_initial()) {
                Some(ContractState::generate_delta_and_update_state(&self.pre_execution_state, &mut self.post_execution_state, &self.key)?)
            } else {
                None
            }
        };
        self.result.updated_state = self.post_execution_state;
        Ok(self.result)
    }

    pub fn eprint(&mut self, args: RuntimeArgs) -> Result<()> {
        let msg_ptr: u32 = args.nth_checked(0)?;
        let msg_len: u32 = args.nth_checked(1)?;
        let res = self.memory.get(msg_ptr, msg_len as usize)?;
        // This should not fail if printing is done properly through eng_wasm eprint!
        let st = str::from_utf8(&res).unwrap_or_default();
        debug_println!("PRINT: {}", st);
        Ok(())
    }

    pub fn gas(&mut self, args: RuntimeArgs) -> Result<()> {
        let amount: u32 = args.nth_checked(0)?;
        self.charge_gas(amount as u64)
    }

    pub fn charge_deployment(&mut self) -> Result<()> {
        let deployed_bytecode_len = self.result.result.len() as u64;
        let gas_for_byte = self.gas_costs.deploy_byte;
        self.charge_gas(deployed_bytecode_len * gas_for_byte)
    }

    pub fn charge_execution(&mut self) -> Result<()> {
        let initial_execution_gas = self.gas_costs.execution;
        self.charge_gas(initial_execution_gas)
    }

    fn charge_gas(&mut self, amount: u64) -> Result<()> {
        if self.charge_gas_if_enough(amount) {
            Ok(())
        } else {
            self.gas_counter = self.gas_limit;
            Err(WasmError::GasLimit)
        }
    }

    fn charge_gas_if_enough(&mut self, amount: u64) -> bool {
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

    pub fn encrypt_with_nonce(&mut self, args: RuntimeArgs) -> Result<()> {
        let message_ptr: u32 = args.nth_checked(0)?;
        let message_len: u32 = args.nth_checked(1)?;
        let message = self.memory.get(message_ptr, message_len as usize)?;

        let key_ptr: u32 = args.nth_checked(2)?;
        let mut key: SymmetricKey = [0u8; SYMMETRIC_KEY_SIZE];
        self.memory.get_into(key_ptr, &mut key)?;

        let iv_ptr: u32 = args.nth_checked(3)?;
        let mut iv: IV = [0u8; IV_SIZE];
        self.memory.get_into(iv_ptr, &mut iv)?;

        let ptr: u32 = args.nth_checked(4)?;
        let enc_message = encrypt_with_nonce(&message, &key, Some(iv))
            .map_err(|err| WasmError::EnclaveError(EnclaveError::SystemError(EnclaveSystemError::CryptoError { err })))?;
        self.memory.set(ptr, &enc_message)?;
        Ok(())
    }

    pub fn decrypt(&mut self, args: RuntimeArgs) -> Result<()> {
        let cipheriv_ptr: u32 = args.nth_checked(0)?;
        let cipheriv_len: u32 = args.nth_checked(1)?;
        let cipheriv = self.memory.get(cipheriv_ptr, cipheriv_len as usize)?;

        let key_ptr: u32 = args.nth_checked(2)?;
        let mut key: SymmetricKey = [0u8; SYMMETRIC_KEY_SIZE];
        self.memory.get_into(key_ptr, &mut key)?;

        let ptr: u32 = args.nth_checked(3)?;
        let message = decrypt(&cipheriv, &key)
            .map_err(|err| WasmError::EnclaveError(EnclaveError::SystemError(EnclaveSystemError::CryptoError { err })))?;
        self.memory.set(ptr, &message)?;
        Ok(())
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
                eng_resolver::ids::REMOVE_STATE_FUNC => {
                    Runtime::remove_from_state(self, args)?;
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
