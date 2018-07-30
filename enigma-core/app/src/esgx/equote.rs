use sgx_types::*;
use std::*;
use common_u::errors;
use failure::Error;

extern { fn ecall_get_signing_address(eid: sgx_enclave_id_t, pubkey: &mut [u8; 42]) -> sgx_status_t; }

// this struct is returned during the process registration back to the surface.
// quote: the base64 encoded quote 
// address : the clear text public key for ecdsa signing and registration
#[derive(Serialize, Deserialize, Debug)]
pub struct GetRegisterResult{
    pub errored : bool,
    pub quote : String, 
    pub address : String,
}


// wrapper function for getting the enclave public sign key (the one attached with produce_quote()) 
// TODO:: replace the error type in the Result once established
pub fn get_register_signing_address(eid: sgx_enclave_id_t) ->Result<String,Error>{
    let mut address: [u8; 42] = [0; 42];
    let status =  unsafe { ecall_get_signing_address(eid, &mut address) };
    if status == sgx_status_t::SGX_SUCCESS {
        let address_str = str::from_utf8(&address).unwrap();
        Ok(address_str.to_owned())
    } else {
        Err(errors::GetRegisterKeyErr {
            status,
            message : String::from("error in get_register_signing_key")
        }.into())
    }
}


 #[cfg(test)]  
 mod test {
    use esgx::general::init_enclave_wrapper;
    use enigma_tools_u::esgx::equote::retry_quote;
     #[test]
     fn test_produce_quote(){ 
            // initiate the enclave 
            let enclave = match init_enclave_wrapper() {
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
        let tested_encoded_quote = match retry_quote(enclave.geteid(), &spid, 8){
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