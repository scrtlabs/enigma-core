use std;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::ptr;

use std::slice;

extern {
    pub fn ecall_test_seal_unseal(eid: sgx_enclave_id_t );
}
extern {
    pub fn ecall_seal_key(eid : sgx_enclave_id_t, retval: *mut sgx_status_t,sealed_log_out : &mut [u8],sealed_log_size: u32)->sgx_status_t;    
}

extern {
    pub fn ecall_unseal_key(eid : sgx_enclave_id_t, retval: *mut sgx_status_t,sealed_log_in : &mut [u8],sealed_log_size: u32)->sgx_status_t;    
}