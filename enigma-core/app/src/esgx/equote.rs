#![allow(dead_code,unused_assignments)]
use std;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::*;
use base64::{encode};


use esgx::general;
use common_u::errors;
//errors 
use failure::Error;


#[link(name = "sgx_tservice")] extern {
    pub fn ecall_get_registration_quote(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, target_info : *const sgx_target_info_t,
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

extern { 
    fn ecall_get_signing_address(eid: sgx_enclave_id_t, pubkey: &mut [u8; 42]) -> sgx_status_t;
}


// this struct is returned during the process registration back to the surface.
// quote: the base64 encoded quote 
// address : the clear text public key for ecdsa signing and registration
#[derive(Serialize, Deserialize, Debug)]
pub struct GetRegisterResult{
    pub errored : bool,
    pub quote : String, 
    pub address : String,
}

// TODO:: handle stat return with error handling 
#[allow(unused_variables, unused_mut)]
pub fn produce_quote(eid: sgx_enclave_id_t, spid : &String) -> Result<String,Error>{
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut stat = sgx_status_t::SGX_SUCCESS;

    let mut target_info = sgx_target_info_t::default();
    let mut gid = sgx_epid_group_id_t::default();
    // create quote
    stat = unsafe{
        sgx_init_quote(&mut target_info ,&mut gid)
    };

    // create report
    let mut report = sgx_report_t::default();
    let _home = general::storage_dir();
    let home = _home.to_str().unwrap();
    stat = unsafe {
        ecall_get_registration_quote(eid, &mut retval, &target_info,
                            &mut report)
    };
    // calc quote size
    let mut quote_size : u32= 0;
    stat = unsafe {
        sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size)
    };
    // get the actual quote
    let quote_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    let v: Vec<u8> = spid.as_bytes().chunks(2).map(|buf|
        u8::from_str_radix(std::str::from_utf8(buf).unwrap(), 16).unwrap()
    ).collect();
    let mut arr = [0; 16];
    arr.copy_from_slice(&v);
    let mut final_spid : sgx_spid_t = sgx_spid_t {id:arr };
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
    let encoded_quote= encode(&the_quote);
    Ok(encoded_quote)
}


// wrapper function for getting the enclave public sign key (the one attached with produce_quote()) 
// TODO:: replace the error type in the Result once established
pub fn get_register_signing_address(eid: sgx_enclave_id_t) ->Result<String,Error>{
    let mut address: [u8; 42] = [0; 42];
    let status =  unsafe {
        ecall_get_signing_address(eid, &mut address)
    };
    if status == sgx_status_t::SGX_SUCCESS {
//        let hex_key = pub_key.iter().fold(String::new(), |mut s, v| {
//                    s.push_str(&format!("{:02x}", v));
//                    s
//        });
//        Ok(hex_key)
        let address_str = str::from_utf8(&address).unwrap();
        Ok(address_str.to_owned())
    } else {
        Err(errors::GetRegisterKeyErr{status:status, 
        message : String::from("error in get_register_signing_key")}.into())
    }
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
        // victors spid = 68A8730E9ABF1829EA3F7A66321E84D0
        let spid = String::from("1601F95C39B9EA307FEAABB901ADC3EE"); // Elichai's SPID
        let tested_encoded_quote = match produce_quote(enclave.geteid(), &spid){
            Ok(encoded_quote)=>{
                encoded_quote
            },
            Err(e)=>{
                println!("[-] Produce quote Err {}, {}", e.cause(), e.backtrace());
                assert_eq!(0,1);
                return;
            }
        };
        println!("-------------------------" );
        println!("{}",tested_encoded_quote);
        println!("-------------------------" );
        enclave.destroy();
        assert!(tested_encoded_quote.len() > 0);
        //assert_eq!(real_encoded_quote, tested_encoded_quote);
     }
 }