
#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]



#[cfg(not(target_env = "sgx"))]
#[macro_use]

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


#[no_mangle]
pub extern "C" fn create_report_t(targetInfo: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
    let reportDataSize : usize = 64;
    let mut report_data = sgx_report_data_t::default();
    // secret data to be attached with the report.
    for i in 0..reportDataSize{
        report_data.d[i] = 1;
    }
    report_data.d[0] = 's' as u8;
    report_data.d[1] = 'e' as u8;
    report_data.d[2] = 'r' as u8;
    report_data.d[3] = 'e' as u8;
    report_data.d[4] = 't' as u8;

    let mut finalReport : sgx_report_t;
    let mut report = match rsgx_create_report(&targetInfo, &report_data) {
        Ok(r) =>{
           *real_report = r;
            sgx_status_t::SGX_SUCCESS
        },
        Err(r) =>{
            println!("Report creationg => failed" );
            r
        },
    };
    sgx_status_t::SGX_SUCCESS
}