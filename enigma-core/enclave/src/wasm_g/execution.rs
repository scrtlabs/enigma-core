//extern crate wasmi;

use std::vec::Vec;
use std::slice;
use std::string::ToString;
use wasmi::{Module, ImportsBuilder, ModuleInstance, memory_units, MemoryInstance};
use common::errors_t::EnclaveError;
use wasm_g::eng_resolver;
use wasm_g::eng_runtime;


pub fn execute_constructor(bytecode: &Vec<u8>) -> Result<Vec<u8>, EnclaveError>{
    // Load wasm binary and prepare it for instantiation.
    let module = Module::from_buffer(&bytecode).unwrap();

    let instantiation_resolver = eng_resolver::ImportResolver::with_limit(16);

    let imports = ImportsBuilder::new().with_resolver("env", &instantiation_resolver);

    // Instantiate a module
/*    let instance = ModuleInstance::new(&module, &imports).
        expect("failed to instantiate wasm module")
        .assert_no_start();

    let mut runtime = eng_runtime::Runtime::new(instantiation_resolver.memory_ref(),Vec::new());

    match instance.invoke_export("call", &[], &mut runtime){
        Ok(_v)=> {
            Ok(runtime.into_result())
        }
        Err(e)=>{
            println!("Error in invocation of the external function: {}", e);
            Err(EnclaveError::ExecutionErr{code: "deployment code".to_string(), err: e.to_string()})
        }
    }*/
    Ok(Vec::new())

}