extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
// networking apt install libzmq3-dev
extern crate zmq; 
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use zmq::*;
use serde_json::*;

use sgx_types::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::vec;


// enigma modules 
mod esgx;
mod evm_u;
mod networking;

use esgx::general;
use esgx::equote;

use networking::surface_server;
use networking::constants;

pub use esgx::general::ocall_get_home;



#[allow(unused_variables, unused_mut)]
fn main() {
    /* this is an example of initiating an enclave */

    let enclave = match esgx::general::init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
//    let spid = String::from("3DDB338BD52EE314B01F1E4E1E84E8AA");
    // let spid = String::from("1601F95C39B9EA307FEAABB901ADC3EE");
    // let tested_encoded_quote = equote::produce_quote(&enclave, &spid);
    // println!("{:?}", &tested_encoded_quote);

    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use esgx::general;
    use esgx::general::init_enclave;
    use sgx_types::*;
    extern { fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t; }

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
        let ret = unsafe { ecall_run_tests(enclave.geteid()) };
        assert_eq!(ret,sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}
