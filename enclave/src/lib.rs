
#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]


#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_types;
extern crate sgx_tse;
extern crate sgx_trts;
extern crate sputnikvm;
extern crate hexutil;
extern crate bigint;
extern crate sputnikvm_network_classic;

use sgx_trts::*;
use sgx_types::*;
use sgx_tse::*;
use std::ptr;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
mod quote_t;

mod evm_t;
use evm_t::call_sputnikvm;
use hexutil::read_hex;
use std::str::from_utf8;

#[no_mangle]
pub extern "C" fn ecall_create_report(targetInfo: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
    let secret = String::from("Isan");
    quote_t::create_report_with_data(&targetInfo ,real_report,&secret)
}

#[no_mangle]
pub extern "C" fn ecall_create_report_with_key(targetInfo: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
    // TODO:: get the sign(pk,sk) 
    //quote_t::create_report_with_data(&targetInfo ,real_report,&secret)
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_seal_data() -> sgx_status_t {
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_evm(code: *const u8, code_len: usize, data: *const u8, data_len: usize, output: *mut u8, vm_status: &mut u8, result_len: &mut usize) -> sgx_status_t {
    let code_slice = unsafe { slice::from_raw_parts(code, code_len) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len) };

    let code = read_hex(from_utf8(code_slice).unwrap()).unwrap();
    let data = read_hex(from_utf8(data_slice).unwrap()).unwrap();

    let mut res = call_sputnikvm(code, data);
    let mut s: &mut [u8] = &mut res.1[..];
    *result_len = s.len();

    *vm_status = res.0;
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), output, s.len());
    }
    sgx_status_t::SGX_SUCCESS
}


