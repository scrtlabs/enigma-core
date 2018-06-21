#![allow(dead_code,unused_assignments,unused_variables)]
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::iter::FromIterator;
//failure 
use common_u::errors;
use failure::Error;
use std::str::from_utf8;


extern {
    fn ecall_evm(eid: sgx_enclave_id_t,
                 retval: *mut sgx_status_t,
                 bytecode: *const u8, bytecode_len: usize,
                 callable: *const u8, callable_len: usize,
                 callable_args: *const u8, callable_args_len: usize,
                 preprocessor: *const u8, preprocessor_len: usize,
                 callback: *const u8, callback_len: usize,
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

pub fn exec_evm(/*enclave: &SgxEnclave*/eid: sgx_enclave_id_t, evm_input: EvmRequest )-> Result<EvmResponse,Error>{
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
fn call_evm(eid: sgx_enclave_id_t, evm_input: EvmRequest) -> (u8, Vec<u8>) {
    let mut out = vec![0u8; MAX_EVM_RESULT];
    let slice = out.as_mut_slice();
    let mut st: u8 = 1;
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut result_length: usize = 0;

    let result = unsafe {
        ecall_evm(eid,
                  &mut retval,
                  evm_input.bytecode.as_ptr() as *const u8,
                  evm_input.bytecode.len(),
                  evm_input.callable.as_ptr() as *const u8,
                  evm_input.callable.len(),
                  evm_input.callable_args.as_ptr(),
                  evm_input.callable_args.len(),
                  evm_input.callback.as_ptr(),
                  evm_input.callback.len(),
                  evm_input.preprocessor.as_ptr(),
                  evm_input.preprocessor.len(),
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
    use super::{EvmRequest,EvmInput};

    fn read_input_from_file(path: &str) -> evm::EvmInput {
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
        let evm_input = EvmRequest {
            bytecode:"606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063ef9fc50b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600080828401905080915050929150505600a165627a7a72305820be9168caee2bd3045c4563ce44f698916986a5ad7b2148f91a35093d31d7211b0029".to_string(),
            callable: "addNumbers(uint,uint)".to_string(),
            callable_args: "f878b83a36373031663638663939343534623433633734373566616534613265613862376630303030313032303330343035303630373038303930613062b83a36343833333235643331323733613333633865626137353236646365666561636337303030313032303330343035303630373038303930613062".to_string(),
            preprocessor: "".to_string(),
            callback : "".to_string(),
        };
        let evm_result = evm::call_evm(enclave.geteid(), evm_input);
        assert_eq!(evm_result.0, 0);
        assert_eq!(evm_result.1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        enclave.destroy();
    }
}