pub mod wasm;

use crate::common_u::errors::EnclaveFailError;
use crate::db::{Delta, DeltaKey, Stype};
use std::{fmt, convert::TryFrom};
use enigma_types::{EnclaveReturn, ExecuteResult, ContractAddress};
use failure::Error;
use sgx_types::*;

#[derive(Clone)]
pub struct WasmTaskResult {
    pub bytecode: Box<[u8]>,
    pub output: Box<[u8]>, // On Deploy this will be the exeCode
    pub delta: Delta,
    pub eth_payload: Box<[u8]>,
    pub eth_contract_addr: [u8; 20],
    pub signature: [u8; 65],
    pub used_gas: u64,
}

pub struct WasmTaskFailure {
    pub output: Box<[u8]>,
    pub signature: [u8; 65],
    pub used_gas: u64,
}

#[derive(Debug)]
pub enum WasmResult{
    WasmTaskResult(WasmTaskResult),
    WasmTaskFailure(WasmTaskFailure),
}

impl Default for WasmTaskResult {
    fn default() -> WasmTaskResult {
        WasmTaskResult {
            bytecode: Default::default(),
            output: Default::default(),
            delta: Default::default(),
            eth_payload: Default::default(),
            eth_contract_addr: Default::default(),
            signature: [0u8; 65],
            used_gas: Default::default()
        }
    }
}

impl Default for  WasmTaskFailure {
    fn default() -> WasmTaskFailure {
        WasmTaskFailure {
            output: Default::default(),
            signature: [0u8; 65],
            used_gas: Default::default()
        }
    }
}

impl fmt::Debug for WasmTaskResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_builder = f.debug_struct("WasmTaskResult");
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

impl fmt::Debug for WasmTaskFailure{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_builder = f.debug_struct("WasmTaskFailure");
        debug_builder.field("output", &self.output);
        debug_builder.field("signature", &(&self.signature[..]));
        debug_builder.field("used_gas", &self.used_gas);
        debug_builder.finish()
    }
}

impl TryFrom<(ExecuteResult, ContractAddress, EnclaveReturn, sgx_status_t)> for WasmResult {
    type Error = Error;
    fn try_from(exec: (ExecuteResult, ContractAddress, EnclaveReturn, sgx_status_t)) -> Result<Self, Self::Error> {
        let get_output  = |exec_result: ExecuteResult| -> Result<Box<[u8]>, Self::Error> {
            if exec_result.output.is_null() {
                bail!("The 'output' pointer in ExecuteResult is null: {:?}", exec_result);
            }
            let box_ptr = exec.0.output as *mut Box<[u8]>;
            let output = unsafe { Box::from_raw(box_ptr) };
            Ok(*output)
        };
        if exec.2 == EnclaveReturn::TaskFailure {
            let mut result: WasmTaskFailure = Default::default();
            result.output = get_output(exec.0)?;
            result.signature = exec.0.signature;
            result.used_gas = exec.0.used_gas;
            Ok(WasmResult::WasmTaskFailure(result))
        }
        else if exec.2 != EnclaveReturn::Success || exec.3 != sgx_status_t::SGX_SUCCESS {
            Err(EnclaveFailError { err: exec.2, status: exec.3 }.into())
        }
        else {
            if exec.0.ethereum_payload_ptr.is_null() || exec.0.delta_ptr.is_null() {
                bail!("One of the pointers in ExecuteResult is null: {:?}", exec.0);
            }

            let mut result: WasmTaskResult = Default::default();
            // If execution does not return any result, then `output` points to empty array []
            result.output = get_output(exec.0)?;
            result.signature = exec.0.signature;
            result.used_gas = exec.0.used_gas;

            // If there is no call to any ethereum contract in the execution, then
            // `eth_contract_addr` is all zeros
            result.eth_contract_addr = exec.0.ethereum_address;

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

            Ok(WasmResult::WasmTaskResult(result))
        }
    }
}
