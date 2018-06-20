#![allow(dead_code,unused_assignments,unused_variables)]
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::iter::FromIterator;
//failure 
use common_u::errors;
use failure::Error;

extern {
    fn ecall_evm(eid: sgx_enclave_id_t,
                 retval: *mut sgx_status_t,
                 code: *const u8, code_len: usize,
                 data: *const u8, data_len: usize,
                 output: *mut u8, vm_status: &mut u8,
                 result_length: &mut usize) -> sgx_status_t;
}


pub struct EvmInput {
    code: String,
    data: String,
}

// this is the input after its being parsed from the server (originally came from surface)

pub struct EvmRequest{
    #[allow(dead_code)]
    bytecode :      String,
    callable :      String, 
    callable_args :  String, 
    preprocessor :  String,
    callback :      String,
}


impl EvmRequest {
     pub fn new(_bytecode:String,_callable:String,_callable_args:String,_preprocessor:String,_callback:String) -> Self {
        EvmRequest {
            bytecode : _bytecode,
            callable : _callable, 
            callable_args : _callable_args, 
            preprocessor : _preprocessor,
            callback : _callback,
        }
    }
}   

// this is the result from the evm computation that will be send to the server and propagated to surface. 
#[derive(Serialize, Deserialize, Debug)]
pub struct EvmResponse{
    errored : bool,
    result : String, 
    signature : String,
}


// this function is called by the the server componenet upon an execevm command from surface
// very likely that this functions will require an SgxEnclave object.

pub fn exec_evm(evm_input: EvmRequest )-> Result<EvmResponse,Error>{
    println!("recieved from the client => " );
    println!("bytecode : {}",evm_input.bytecode );
    println!("callable : {}",evm_input.callable );
    println!("callable_args : {}",evm_input.callable_args );
    println!("callback : {}",evm_input.callback );
    println!("preprocessor : {}",evm_input.preprocessor );
    // this never happens, just an example of WHEN this function is implemented how to use the error type related to that computation.
    if false {
        return Err(errors::ExecEvmErr{status:sgx_status_t::SGX_SUCCESS, message : String::from("execevm error example")}.into());
    }
    Ok(EvmResponse{
        errored:false,
        result : String::from("the evm result :o"), 
        signature : String::from("the evm signature :o")})

}

// TODO:: handle error and failure correctly with the 'result' variable returned from the enclave
// This should be changed
// the length of the result returned by EVM should be checked in advance
const MAX_EVM_RESULT: usize = 1000000;
fn call_evm(enclave: &SgxEnclave, input: EvmInput) -> (u8, Vec<u8>) {
    let code = input.code;
    let data = input.data;

    let mut out = vec![0u8; MAX_EVM_RESULT];
    let slice = out.as_mut_slice();
    let mut st: u8 = 1;
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut result_length: usize = 0;

    let result = unsafe {
        ecall_evm(enclave.geteid(),
                  &mut retval,
                  code.as_ptr() as *const u8,
                  code.len(),
                  data.as_ptr() as *const u8,
                  data.len(),
                  slice.as_mut_ptr() as *mut u8,
                  &mut st,
                  &mut result_length)
    };
    let part = Vec::from_iter(slice[0..result_length].iter().cloned());
    (st, part)
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code,unused_assignments,unused_variables)]
    use esgx;
    use std::fs::File;
    use std::io::{ BufReader, BufRead};
    use evm_u::evm;

    fn read_input_from_file(path: &str) -> evm::EvmInput {
        println!("Path {}", path);
        let file = match File::open(&path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", path,
                               why),
            Ok(file) => file,
        };

        let mut lines = BufReader::new(file).lines();
        let result = evm::EvmInput {
            data: lines.next().unwrap().unwrap(),
            code: lines.next().unwrap().unwrap(),
        };
        result
    }

    #[test]
    pub fn add_function() {
        let enclave = match esgx::general::init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                panic!("[-] Init Enclave Failed {}!", x.as_str());
            }
        };
        let evm_input = read_input_from_file("../app/tests/evm_input_files/input");
        let evm_result = evm::call_evm(&enclave, evm_input);
        assert_eq!(evm_result.0, 0);
        assert_eq!(evm_result.1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        enclave.destroy();
    }
}