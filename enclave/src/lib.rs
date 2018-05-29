
#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]



#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_types;
extern crate sgx_tse;
extern crate sgx_tdh;   
extern crate sgx_tservice;
extern crate sgx_trts;

use sgx_trts::*;
use sgx_tservice::*;
use sgx_types::*;
use sgx_tdh::*;
use sgx_tse::*;
use core::ptr;

use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
mod quote_t;



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

