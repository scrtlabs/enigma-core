
extern crate base64;
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;

// enigma modules 
mod esgx;
        
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
    // test quote 
    let encoded_quote = esgx::equote::test_quote(&enclave);
    println!("{}",encoded_quote );

    enclave.destroy();
}