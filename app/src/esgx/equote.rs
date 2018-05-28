extern crate sgx_types;
extern crate sgx_urts;
extern crate std;
use sgx_types::*;

use sgx_urts::SgxEnclave;
use std::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::ptr;

extern crate base64;
use base64::{encode, decode};

use std::slice;


#[link(name = "sgx_tservice")] extern {
    fn ecall_create_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, targetInfo : *const sgx_target_info_t,
     report: *mut sgx_report_t) -> sgx_status_t ;
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
pub fn test_quote(enclave : &SgxEnclave) -> String{
     let mut retval = sgx_status_t::SGX_SUCCESS; 
    // test 2 

        let mut stat = sgx_status_t::SGX_SUCCESS; 
    
        let mut targetInfo = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        // create quote 
        stat = unsafe{
            sgx_init_quote(&mut targetInfo ,&mut gid)
        };
        // create report
        let mut report = sgx_report_t::default(); 
        let mut retval : sgx_status_t = sgx_status_t::SGX_SUCCESS;
        stat = unsafe {
            ecall_create_report(enclave.geteid(),&mut retval,&targetInfo,&mut report)
        };
        // calc quote size  
        let mut quoteSize : u32= 0;
        stat = unsafe {
            sgx_calc_quote_size(std::ptr::null(), 0, &mut quoteSize)
        };
        // get the actual quote 
        let SGX_UNLINKABLE_SIGNATURE :u32 = 0;
        let quoteType = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

        // my spid {0x3D,0xDB,0x33,0x8B,0xD5,0x2E,0xE3,0x14,0xB0,0x1F,0x1E,0x4E,0x1E,0x84,0xE8,0xAA};
        let spid =  [0x3D,0xDB,0x33,0x8B,0xD5,0x2E,0xE3,0x14,0xB0,0x1F,0x1E,0x4E,0x1E,0x84,0xE8,0xAA];
        let mut finalSPID : sgx_spid_t = sgx_spid_t{id:spid};
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
    use esgx::equote::test_quote;
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
                return;
            },
        };
        // produce a quote 
        let tested_encoded_quote = test_quote(&enclave);
        let real_encoded_quote =String::from("AgAAAMoKAAAGAAUAAAAAAD3bM4vVLuMUsB8eTh6E6Kp/E1RY66uLmOMIjzfQyezNAgT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHkrLX2+Ejdwyr3mxSRVN4gQ2NSPUr49XUfhnZjsXdXYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABzZXJldAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBqAIAAIg3Q+ks8tnXkrRX3WHTxiqDsbCiRdxFazBXzI2erE7N9EHAbI5p9wT+n3u51CNLoMwMFG422D96pYy5eb8gbEU3cFYTSQvwAONCSRuwkWTD5rDd5s3syLvXVC7iEWCsW9AIhlvGHvDo8YnYZxC360VZALP7WCUQUut0/FaTvMrx12KjveO4Q8iO1OTBBPXLBJTbeym+xU8xOInQZiROb/fImVUzgJBF079FZJGDVgql/FXUqvk6MVn1MullKLDuDPOQRwahHbNRbNK6kfpbIwhzMvwg/chvRLWBltSohjERvwmHLKUlj9rKPFTZLmxkFcMgdRAGOLfsgvf3VB2p9xZOASqbYVUCg2gXiUwWyL6thjZoED1PPeLaolzE5TpF3LOgCoa3cAeaPVwpzWgBAABngaRt6sjL/wvcMJRVnaL7R85Uld7a0HxoEI6gXP3WHJ0yN64nTZHs/7QSjpC21IzVUbacNFtR+WurGOUM3+beJQKOdCnGyZAreK2gt/IDmoRLNP9pNfRHM3aiUgdaQOsT9r8Dn15KMxsVC0E463A4EqOCzBgsMfRNoODo7yHXcMKqEPbnqSM7HT3WmkWIaFG6g6WifLvTMomt6MRWYIPHdn0BP+a7Q0qtzZuPPD/DUGrd9JelARsPkUmmPuv25mFj25SOyepcrDbv4ZD7KO0GcX8Xwsgrc28+Yn5gyN32WnODPtC7Nl0ASp8Oh7qv8UEHg2SaSRBnxXlgycSF/8uikZiQzV26dCG9bIlDG4a9tgGNv09f9GQft4WmpmIlXzwMnAauaRZudK2seSPpMwHECSzeIy6Y+mcix3Q42NPg5j78gqDpEfAjTTyL02EcAr3nswtEYRwH/wEtp68T6PXWebRbaVIl26jPYfD3K92lCZBXn72hGJkA");
        enclave.destroy();
        assert_eq!(real_encoded_quote, tested_encoded_quote);
     }
 }