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
    // quote test 

    // let spid = String::from("3DDB338BD52EE314B01F1E4E1E84E8AA");
    // let mut encoded = esgx::equote::produce_quote(&enclave, &spid);
    // println!("{}",encoded );
    
    // sealing test 

    //unsafe {ecall_test_seal_unseal(enclave.geteid());};

    let mut ret = sgx_status_t::SGX_SUCCESS;
    let mut sealed_log_result:[u8;2048] = [0;2048];
    // seal 
    ret = unsafe{
        esgx::estorage::ecall_seal_key(enclave.geteid(),&mut ret,&mut sealed_log_result, 2048)
    };
    // unseal 
    ret = unsafe{
       esgx::estorage::ecall_unseal_key(enclave.geteid(), &mut ret , &mut sealed_log_result , 2048)
    };
    enclave.destroy();
}   