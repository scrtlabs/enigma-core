extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
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
use esgx::equote;
pub use esgx::general::ocall_get_home;

extern { fn ecall_get_signing_pubkey(eid: sgx_enclave_id_t, pubkey: &mut [u8; 64]) -> sgx_status_t; }

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
    let spid = String::from("1601F95C39B9EA307FEAABB901ADC3EE");
    let tested_encoded_quote = equote::produce_quote(&enclave, &spid);
    println!("{:?}", &tested_encoded_quote);

    let mut pubme: [u8; 64] = [0; 64];
    unsafe {ecall_get_signing_pubkey(enclave.geteid(), &mut pubme)};
    println!("Returned Pub: {:?}", &pubme[..]);
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
