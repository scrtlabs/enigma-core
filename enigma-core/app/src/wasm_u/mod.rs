pub mod wasm;

use crate::db::{Delta, DeltaKey, Stype};
use std::{fmt, mem, convert::TryFrom};
use enigma_types::ExecuteResult;
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

impl TryFrom<ExecuteResult> for WasmResult {
    type Error = Error;
    fn try_from(exec: ExecuteResult) -> Result<Self, Self::Error> {
        if exec.output.is_null() || exec.ethereum_payload_ptr.is_null() {
            bail!("One of the pointers in ExecuteResult is null: {:?}", exec);
        }

        let mut result: WasmResult = Default::default();
        result.signature = exec.signature;
        result.eth_contract_addr = exec.ethereum_address;

        let box_ptr = exec.output as *mut Box<[u8]>;
        let output = unsafe { Box::from_raw(box_ptr) };
        result.output = *output;

        let box_payload_ptr = exec.ethereum_payload_ptr as *mut Box<[u8]>;
        let payload = unsafe { Box::from_raw(box_payload_ptr) };
        result.eth_payload = *payload;

        // TODO: Is it possible to have no delta or not?. please decide this. @elichai @moria
        if !exec.delta_ptr.is_null() && exec.delta_hash != [0u8; 32] {
            let box_ptr = exec.delta_ptr as *mut Box<[u8]>;
            let delta_data = unsafe { Box::from_raw(box_ptr) };

            result.delta.value = delta_data.to_vec();
            result.delta.key = DeltaKey::new(exec.delta_hash, Stype::Delta(exec.delta_index));

        } else {
            bail!("Weird delta results")
        }
        Ok(result)
    }
}
