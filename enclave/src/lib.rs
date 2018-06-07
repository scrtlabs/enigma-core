
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
// sealing 
extern crate sgx_tseal;
extern crate sgx_rand;
//
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
mod storage_t;



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

#[allow(unused_variables, unused_mut)]
#[no_mangle]
pub extern "C" fn ecall_test_seal_unseal() {    
   //input 
    let mut data = storage_t::SecretKeyStorage::default();
    data.version = 0x1234;
    for i in 0..32{
        data.data[i] = 'i' as u8;
    }
   // output 
   let mut sealed_log_arr:[u8;storage_t::SEAL_LOG_SIZE] = [0;storage_t::SEAL_LOG_SIZE];
   storage_t::seal_key(&data,&mut sealed_log_arr);
   let udata =  storage_t::unseal_key(&mut sealed_log_arr);
   println!("unsealed data = {:?}", udata);   
}

#[allow(unused_variables, unused_mut)]
#[no_mangle]
pub extern "C" fn ecall_seal_key(sealed_log_out : &mut [u8])->sgx_status_t{    
   //mock key input 
    let mut data = storage_t::SecretKeyStorage::default();
    data.version = 0x1234;
    for i in 0..32{
        data.data[i] = 'i' as u8;
    }
   // output 
   storage_t::seal_key(&data,sealed_log_out);
   sgx_status_t::SGX_SUCCESS
}


// TODO:: main question => return struct ?? 
#[allow(unused_variables, unused_mut)]
#[no_mangle]
pub extern "C" fn ecall_unseal_key(sealed_log_in : &mut [u8])->sgx_status_t{    
    let unsealed_data = storage_t::unseal_key(sealed_log_in);
    println!("Unseal key {:? }",unsealed_data );
    sgx_status_t::SGX_SUCCESS
}
