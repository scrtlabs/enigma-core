use std::vec::Vec;
use std::slice;
use std::string::ToString;
use std::borrow::ToOwned;
use wasmi::{Module, ImportsBuilder, ModuleInstance, memory_units, MemoryInstance, RuntimeValue};
use common::errors_t::EnclaveError;
use enigma_runtime_t::eng_resolver;
use enigma_runtime_t::Runtime;
use enigma_runtime_t::state::ContractState;


pub fn execute(code: &Vec<u8>, callable: &str) -> Result<Vec<u8>, EnclaveError> {
    let module = Module::from_buffer(&code).unwrap();

    let instantiation_resolver = eng_resolver::ImportResolver::with_limit(32);

    let imports = ImportsBuilder::new().with_resolver("env", &instantiation_resolver);

    // Instantiate a module
    let instance = ModuleInstance::new(&module, &imports).
        expect("failed to instantiate wasm module")
        .assert_no_start();

    let mut runtime = Runtime::new(instantiation_resolver.memory_ref(), Vec::new(), "Enigma".to_string());

    match instance.invoke_export(callable, &[], &mut runtime) {
        Ok(_v) => {
            unsafe {
                let result = runtime.into_result();
                Ok(result.to_owned())
            }
        }
        Err(e) => {
            println!("Error in invocation of the external function: {}", e);
            Err(EnclaveError::ExecutionErr { code: "deployment code".to_string(), err: e.to_string() })
        }
    }
}

pub fn execute_constructor(code: &Vec<u8>) -> Result<Vec<u8>, EnclaveError>{
    execute(code, "call")
}