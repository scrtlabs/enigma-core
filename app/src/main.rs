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
        

extern {
    pub fn ecall_test_seal_unseal(eid: sgx_enclave_id_t );
}
extern {
    //pub fn ecall_seal_key(eid : sgx_enclave_id_t, retval: *mut sgx_status_t, sealed_log_out :*mut ::uint8_t )->sgx_status_t ;
    pub fn ecall_seal_key(eid : sgx_enclave_id_t, retval: *mut sgx_status_t,sealed_log_out : &mut [u8])->sgx_status_t;    
}
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

    // unsafe {ecall_test_seal_unseal(enclave.geteid());};

    let mut ret = sgx_status_t::SGX_SUCCESS;
    let mut sealed_log_result:[u8;2048] = [0;2048];
    unsafe{
        ecall_seal_key(enclave.geteid(),&mut ret,&mut sealed_log_result);
    }
    enclave.destroy();
}   