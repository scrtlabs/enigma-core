use sgx_types::*;
use failure::Error;
use base64;
use std::thread::sleep;
use std::{self, time};
use common_u::errors;

#[link(name = "sgx_tservice")] extern {
    pub fn ecall_get_registration_quote(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, target_info : *const sgx_target_info_t,
                                        report: *mut sgx_report_t) -> sgx_status_t ;
}

extern {
    pub fn sgx_init_quote(p_target_info: * mut sgx_target_info_t, p_gid: * mut sgx_epid_group_id_t) -> sgx_status_t;
}

extern {
    pub fn sgx_calc_quote_size(p_sig_rl: * const ::uint8_t, sig_rl_size: ::uint32_t, p_quote_size: * mut ::uint32_t) -> sgx_status_t;
}

extern {
    pub fn sgx_get_quote(p_report: * const sgx_report_t,
                         quote_type: sgx_quote_sign_type_t,
                         p_spid: * const sgx_spid_t,
                         p_nonce: * const sgx_quote_nonce_t,
                         p_sig_rl: * const ::uint8_t,
                         sig_rl_size: ::uint32_t,
                         p_qe_report: * mut sgx_report_t,
                         p_quote: * mut sgx_quote_t,
                         quote_size: ::uint32_t) -> sgx_status_t;
}

pub fn retry_quote(eid: sgx_enclave_id_t, spid : &String, times: usize) -> Result<String, Error> {
    let mut quote = String::new();
    for _ in 0..times {
        quote = produce_quote(eid, spid)?;
        if !quote.chars().all(|cur_c| cur_c == 'A') { return Ok(quote); }
        sleep(time::Duration::new(2, 0));
    }
    Err(errors::QuoteErr{ message : quote }.into())
}

// TODO:: handle stat return with error handling
#[allow(unused_variables, unused_mut)]
pub fn produce_quote(eid: sgx_enclave_id_t, spid : &String) -> Result<String,Error>{
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut stat = sgx_status_t::SGX_SUCCESS;

    let mut target_info = sgx_target_info_t::default();
    let mut gid = sgx_epid_group_id_t::default();

    // create quote
    stat = unsafe{ sgx_init_quote(&mut target_info ,&mut gid) };

    // create report
    let mut report = sgx_report_t::default();
    stat = unsafe { ecall_get_registration_quote(eid, &mut retval, &target_info, &mut report) };
    // calc quote size
    let mut quote_size : u32= 0;
    stat = unsafe { sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size) };

    // get the actual quote
    let quote_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    let v: Vec<u8> =
        spid.as_bytes().chunks(2).map(|buf|
            u8::from_str_radix(std::str::from_utf8(buf).unwrap(), 16).unwrap() ).collect();
    let mut arr = [0; 16];
    arr.copy_from_slice(&v);

    let final_spid : sgx_spid_t = sgx_spid_t { id:arr };
    let mut the_quote = vec![0u8; quote_size as usize].into_boxed_slice();
    let nonce =  sgx_quote_nonce_t::default();;
    let mut qe_report = sgx_report_t::default();

    stat = unsafe {
        sgx_get_quote(&report,
                      quote_type ,
                      &final_spid,
                      &nonce,
                      std::ptr::null(),
                      0,
                      &mut qe_report,
                      the_quote.as_mut_ptr() as *mut sgx_quote_t,
                      quote_size )
    };
    let encoded_quote = base64::encode(&the_quote);
    Ok(encoded_quote)
}