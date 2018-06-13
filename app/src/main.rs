extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
// networking apt install libzmq3-dev
extern crate zmq; 
extern crate serde_json;

use sgx_types::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::vec;


// enigma modules 
mod esgx;
mod evm_u;

use esgx::general;

#[allow(unused_variables, unused_mut)]
fn main() { 

    /* this is an example of initiating an enclave */

    // let enclave = match esgx::general::init_enclave() {
    //     Ok(r) => {
    //         println!("[+] Init Enclave Successful {}!", r.geteid());
    //         r
    //     },
    //     Err(x) => {
    //         println!("[-] Init Enclave Failed {}!", x.as_str());
    //         return;
    //     },
    // };

    //    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use esgx::general;
    use esgx::general::init_enclave;
    use sgx_types::*;
    extern { fn ecall_run_tests(eid: sgx_enclave_id_t); }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        let mut ret : sgx_status_t = sgx_status_t::SGX_SUCCESS;
        unsafe { ecall_run_tests(enclave.geteid());}
        assert_eq!(ret,sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}
