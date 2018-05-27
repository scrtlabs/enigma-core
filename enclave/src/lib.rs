// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

#[no_mangle]
pub extern "C" fn ecall_create_report(targetInfo: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
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

