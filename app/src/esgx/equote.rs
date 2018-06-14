extern crate base64;
use std;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::ptr;
use base64::{encode, decode};
use std::slice;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use esgx::general;


#[link(name = "sgx_tservice")] extern {
    pub fn ecall_create_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, target_info : *const sgx_target_info_t,
                               report: *mut sgx_report_t, home_ptr: *const u8, home_len: usize) -> sgx_status_t ;
}
#[link(name = "sgx_uae_service")] extern {
    pub fn sgx_init_quote(p_target_info: * mut sgx_target_info_t, p_gid: * mut sgx_epid_group_id_t) -> sgx_status_t;
}
#[link(name = "sgx_uae_service")] extern {
    pub fn sgx_calc_quote_size(p_sig_rl: * const ::uint8_t, sig_rl_size: ::uint32_t, p_quote_size: * mut ::uint32_t) -> sgx_status_t;        
}

#[link(name = "sgx_uae_service")] extern {
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

#[allow(unused_variables, unused_mut)]
pub fn produce_quote(enclave : &SgxEnclave, spid : &String) -> String{
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut stat = sgx_status_t::SGX_SUCCESS;

    let mut targetInfo = sgx_target_info_t::default();
    let mut gid = sgx_epid_group_id_t::default();

    // create quote
    stat = unsafe{
        sgx_init_quote(&mut targetInfo ,&mut gid)
    };

    // create report
    let mut report = sgx_report_t::default();
    let _home = general::storage_dir();
    let home = _home.to_str().unwrap();
    stat = unsafe {
        ecall_create_report(enclave.geteid(), &mut retval, &targetInfo,
                            &mut report ,home.as_ptr() as * const u8, home.len())
    };
    // calc quote size
    let mut quoteSize : u32= 0;
    stat = unsafe {
        sgx_calc_quote_size(std::ptr::null(), 0, &mut quoteSize)
    };
    // get the actual quote
    let SGX_UNLINKABLE_SIGNATURE :u32 = 0;
    let quoteType = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    let v: Vec<u8> = spid.as_bytes().chunks(2).map(|buf|
        u8::from_str_radix(std::str::from_utf8(buf).unwrap(), 16).unwrap()
    ).collect();
    let mut arr = [0; 16];
    arr.copy_from_slice(&v);
    let mut finalSPID : sgx_spid_t = sgx_spid_t {id:arr };
    let mut theQuote = vec![0u8; quoteSize as usize].into_boxed_slice();
    let nonce =  sgx_quote_nonce_t::default();;
    let mut qeReport = sgx_report_t::default();

    stat = unsafe {
        sgx_get_quote(&report,
        quoteType ,
        &finalSPID,
        &nonce,
        std::ptr::null(),
        0,
        &mut qeReport,
        theQuote.as_mut_ptr() as *mut sgx_quote_t,
        quoteSize )
    };
    encode(&theQuote)
}


// unit tests 

 #[cfg(test)]  
 mod test {
    use esgx::general::init_enclave;
    use esgx::equote::produce_quote;
     #[test]
     fn test_produce_quote(){ 
            // initiate the enclave 
            let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        // produce a quote 
        // isans SPID = "3DDB338BD52EE314B01F1E4E1E84E8AA"
        let spid = String::from("3DDB338BD52EE314B01F1E4E1E84E8AA");
        let tested_encoded_quote = produce_quote(&enclave, &spid);
        enclave.destroy();
        assert!(tested_encoded_quote.len() > 0);
        //assert_eq!(real_encoded_quote, tested_encoded_quote);
     }
 }