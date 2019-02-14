pub mod wasm;

use crate::db::{Delta, DeltaKey, Stype};
use std::{fmt, mem, convert::TryFrom};
use enigma_types::{ExecuteResult, ContractAddress};
use failure::Error;

#[derive(Clone)]
pub struct WasmResult {
    pub bytecode: Box<[u8]>,
    pub output: Box<[u8]>, // On Deploy this will be the exeCode
    pub delta: Delta,
    pub eth_payload: Box<[u8]>,
    pub eth_contract_addr: [u8; 20],
    pub signature: [u8; 65],
    pub used_gas: u64,
}

impl Default for WasmResult {
    fn default() -> WasmResult {
        unsafe { mem::zeroed() }
    }
}

impl fmt::Debug for WasmResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_builder = f.debug_struct("WasmResult");
        debug_builder.field("bytecode", &self.bytecode);
        debug_builder.field("output", &self.output);
        debug_builder.field("delta", &self.delta);
        debug_builder.field("eth_payload", &self.eth_payload);
        debug_builder.field("eth_contract_addr", &self.eth_contract_addr);
        debug_builder.field("signature", &(&self.signature[..]));
        debug_builder.field("used_gas", &self.used_gas);
        debug_builder.finish()
    }
}

impl TryFrom<(ExecuteResult, ContractAddress)> for WasmResult {
    type Error = Error;
    fn try_from(exec: (ExecuteResult, ContractAddress)) -> Result<Self, Self::Error> {
        if exec.0.output.is_null() || exec.0.ethereum_payload_ptr.is_null() || exec.0.delta_ptr.is_null(){
            bail!("One of the pointers in ExecuteResult is null: {:?}", exec.0);
        }

        let mut result: WasmResult = Default::default();
        result.signature = exec.0.signature;
        result.used_gas = exec.0.used_gas;

        // If there is no call to any ethereum contract in the execution, then
        // `eth_contract_addr` is all zeros
        result.eth_contract_addr = exec.0.ethereum_address;

        // If execution does not return any result, then `output` points to empty array []
        let box_ptr = exec.0.output as *mut Box<[u8]>;
        let output = unsafe { Box::from_raw(box_ptr) };
        result.output = *output;

        // If there is no call to any ethereum contract in the execution, then
        // `ethereum_payload_ptr` points to empty array []
        let box_payload_ptr = exec.0.ethereum_payload_ptr as *mut Box<[u8]>;
        let payload = unsafe { Box::from_raw(box_payload_ptr) };
        result.eth_payload = *payload;

        // If state was not changed by the execution (which means that delta is empty),
        // then `delta_ptr` points to empty array []
        let box_ptr = exec.0.delta_ptr as *mut Box<[u8]>;
        let delta_data = unsafe { Box::from_raw(box_ptr) };

        result.delta.value = delta_data.to_vec();
        result.delta.key = DeltaKey::new(exec.1, Stype::Delta(exec.0.delta_index));

        Ok(result)
    }
}
