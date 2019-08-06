
use parity_wasm::io::Cursor;
use parity_wasm::elements::{self, Deserialize};
use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, FailedTaskError, FailedTaskError::*};
use wasmi::{ImportsBuilder, Module, ModuleInstance, ModuleRef};
pub use gas::{gas_rules, WasmCosts, RuntimeWasmCosts};
use eng_resolver;
use Runtime;
use crate::data::{ContractState};
use enigma_types::StateKey;

use std::boxed::Box;
use std::vec::Vec;
use std::string::{String, ToString};

pub struct WasmEngine {
    pub instance: ModuleRef,
    pub runtime: Runtime,
}

impl WasmEngine {

    pub fn new(code: &[u8], gas_limit: u64, args: Vec<u8>, state: ContractState, function_name: String, args_types: String, key: StateKey) -> Result<WasmEngine, EnclaveError> {
        let module = Self::create_module(code)?;
        let instantiation_resolver = eng_resolver::ImportResolver::with_limit(128);
        let imports = ImportsBuilder::new().with_resolver("env", &instantiation_resolver);
        // TODO: Change the assert here: https://github.com/paritytech/wasmi/issues/172
        let instance = ModuleInstance::new(&module, &imports)?.assert_no_start();
        let runtime = Runtime::new(instantiation_resolver.memory_ref(), gas_limit, args, state, function_name, args_types, key, RuntimeWasmCosts::default());
        Ok(WasmEngine { instance, runtime })
    }

    pub fn create_module(code: &[u8]) -> ::std::result::Result<Box<Module>, EnclaveError> {
        let mut cursor = Cursor::new(&code[..]);
        let deserialized_module = elements::Module::deserialize(&mut cursor)?;
        if deserialized_module.memory_section().map_or(false, |ms| ms.entries().len() > 0) {
            // According to WebAssembly spec, internal memory is hidden from embedder and should not
            // be interacted with. So parity disable this kind of modules at decoding level.
            return Err(FailedTaskError(WasmModuleCreationError {
                code: "creation of WASM module".to_string(),
                err: "Malformed wasm module: internal memory".to_string() }));
        }
        let wasm_costs = WasmCosts::default();
        let contract_module = pwasm_utils::inject_gas_counter(deserialized_module, &gas_rules(&wasm_costs))?;
        let limited_module = pwasm_utils::stack_height::inject_limiter(contract_module, wasm_costs.max_stack_height)?;

        let module = wasmi::Module::from_parity_wasm_module(limited_module)?;
        Ok(Box::new(module))
    }
}