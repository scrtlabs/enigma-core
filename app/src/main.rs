
extern crate base64;
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;

// enigma modules 
pub mod esgx;
        
#[allow(unused_variables, unused_mut)]
fn main() { 
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
    // listen on port :X 
    // dispatch reques => dispatcher 
    // dispatcher => run command 
    // return result => async 


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