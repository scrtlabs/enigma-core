extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
use sgx_types::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;

// enigma modules 
pub mod esgx;
pub mod evm_u;

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
    let spid = String::from("3DDB338BD52EE314B01F1E4E1E84E8AA");
    let mut encoded = esgx::equote::produce_quote(&enclave, &spid);
    println!("{}",encoded );
    enclave.destroy();
}

#[cfg(test)]
mod tests {
    extern { fn ecall_run_tests(); }
    #[test]
    pub fn test_enclave_internal() {
        unsafe { ecall_run_tests(); }
    }

}