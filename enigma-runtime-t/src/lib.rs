#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_tools_t;
extern crate json_patch;
extern crate wasmi;
extern crate hexutil;

use wasmi::{MemoryRef, RuntimeArgs, RuntimeValue, Error as InterpreterError, Trap, TrapKind, Externals, FromRuntimeValue};
use std::vec::Vec;
use std::string::String;
use std::string::ToString;
use std::borrow::ToOwned;
use enigma_tools_t::common::errors_t::EnclaveError;
use std::str::from_utf8;
use hexutil::read_hex;

pub mod state;
pub mod eng_resolver;
use state::IOInterface;
use state::ContractState;


pub struct Runtime {
    memory: MemoryRef,
    args: Vec<u8>,
    result: Vec<u8>,
    state: ContractState,
}

impl Runtime {

    pub fn new(memory: MemoryRef, args: Vec<u8>, contract_id: String) -> Runtime {
        Runtime {
            memory: memory,
            args: args,
            result: Vec::new(),
            state: ContractState::new(&contract_id),
        }
    }

    pub fn from_memory(&mut self, args: RuntimeArgs) -> Result<(), EnclaveError> {
        let value: u32 = args.nth_checked(0).unwrap();
        let value_len: i32 = args.nth_checked(1).unwrap();
        let mut buf = Vec::with_capacity(value_len as usize);
        for i in 0..value_len{
            buf.push(0);
        }
        match self.memory.get_into(0, &mut buf[..]){
            Ok(v) => {
                match self.memory.set(value, &buf[..]){
                    Ok(v) => {
                        self.result = match self.memory.get(0, value_len as usize){
                            Ok(v)=>v,
                            Err(e)=>return Err(EnclaveError::ExecutionErr{code: "ret code".to_string(), err: "".to_string()}),
                        };
                    },
                    Err(e) => return Err(EnclaveError::ExecutionErr{code: "memory".to_string(), err: e.to_string()}),
                }
                Ok(())
            },
            Err(e) => return Err(EnclaveError::ExecutionErr{code: "memory".to_string(), err: e.to_string()}),
        }
    }

    pub fn read_state (&mut self, args: RuntimeArgs) -> Result<i32, EnclaveError> {
        let key = args.nth_checked(0);
        let key_len: u32 = args.nth_checked(1).unwrap();
        let mut buf = Vec::with_capacity(key_len as usize);
        for i in 0..key_len{
            buf.push(0);
        }
        match self.memory.get_into(key.unwrap(), &mut buf[..]){
            Ok(v) => v,
            Err(e) => return Err(EnclaveError::ExecutionErr{code: "read state".to_string(), err: e.to_string()}),
        }
        let key1 = from_utf8(&buf).unwrap();
//        match self.state.read_key::<String>(key1){
          match self.state.read_key::<Vec<u8>>(key1){
            Ok(v) => {
                // value = read_hex(&v).unwrap();
                self.memory.set(0, &v);
                Ok(v.len() as i32)
            },
            Err(e) => return Err(EnclaveError::ExecutionErr{code: "read state".to_string(), err: e.to_string()}),
        }

    }

    pub fn write_state (&mut self, args: RuntimeArgs) -> Result<(), EnclaveError>{
        let key = args.nth_checked(0);
        let key_len: u32 = args.nth_checked(1).unwrap();
        let value: u32 = args.nth_checked(2).unwrap();
        let value_len: u32 = args.nth_checked(3).unwrap();
        let mut buf = Vec::with_capacity(key_len as usize);
        for i in 0..key_len{
            buf.push(0);
        }
        match self.memory.get_into(key.unwrap(), &mut buf[..]){
            Ok(v) => v,
            Err(e) => return Err(EnclaveError::ExecutionErr{code: "write state".to_string(), err: e.to_string()}),
        }
        let mut val = Vec::with_capacity(value_len as usize);
        for i in 0..value_len{
            val.push(0);
        }
        match self.memory.get_into(value, &mut val[..]){
            Ok(v) => v,
            Err(e) => return Err(EnclaveError::ExecutionErr{code: "write state".to_string(), err: e.to_string()}),
        }
        let key1 = from_utf8(&buf).unwrap();
        //let value1 = from_utf8(&val).unwrap();
//        self.state.write_key(key1, json!(value1)).unwrap();
        self.state.write_key(key1, json!(val)).unwrap();
        Ok(())
    }

    pub fn ret(&mut self, args: RuntimeArgs) -> Result<(), EnclaveError> {
        let ptr: u32 = args.nth_checked(0)?;
        let len: u32 = args.nth_checked(1)?;

        self.result = match self.memory.get(ptr, len as usize){
            Ok(v)=>v,
            Err(e)=>return Err(EnclaveError::ExecutionErr{code: "ret code".to_string(), err: "".to_string()}),
        };
        Ok(())
    }

    /// Destroy the runtime, returning currently recorded result of the execution
    pub fn into_result(self) -> Vec<u8> {
        self.result.to_owned()
    }

}

impl Externals for Runtime {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            eng_resolver::ids::RET_FUNC => {
                &mut Runtime::ret(self, args);
                Ok(None)
            }
            eng_resolver::ids::WRITE_STATE_FUNC => {
                &mut Runtime::write_state(self, args);
                Ok(None)
            }
            eng_resolver::ids::READ_STATE_FUNC => {
                Ok(Some(RuntimeValue::I32(Runtime::read_state(self, args).unwrap())))
            }
            eng_resolver::ids::FROM_MEM_FUNC => {
                &mut Runtime::from_memory(self, args);
                Ok(None)
            }
            _ => panic!("Unimplemented function at {}", index),
        }
    }
}


pub mod tests {
    pub fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
