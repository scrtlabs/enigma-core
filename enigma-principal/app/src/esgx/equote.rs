use common_u::errors;
use failure::Error;
use sgx_types::*;
use std::str;

extern "C" {
    fn ecall_get_signing_address(eid: sgx_enclave_id_t, pubkey: &mut [u8; 20]) -> sgx_status_t;
}
extern "C" {
    fn ecall_get_ethereum_address(eid: sgx_enclave_id_t, pubkey: &mut [u8; 20]) -> sgx_status_t;
}

extern "C" {
    fn ecall_sign_ethereum(eid: sgx_enclave_id_t, data: &[u8; 32], sig: &mut [u8; 65]) -> sgx_status_t;
}
// this struct is returned during the process registration back to the surface.
// quote: the base64 encoded quote
// address : the clear text public key for ecdsa signing and registration
#[derive(Serialize, Deserialize, Debug)]
pub struct GetRegisterResult {
    pub errored: bool,
    pub quote: String,
    pub address: String,
}

// wrapper function for getting the enclave public sign key (the one attached with produce_quote())
#[logfn(TRACE)]
pub fn get_register_signing_address(eid: sgx_enclave_id_t) -> Result<[u8; 20], Error> {
    let mut address = [0u8; 20];
    let status = unsafe { ecall_get_signing_address(eid, &mut address) };
    if status == sgx_status_t::SGX_SUCCESS {
        Ok(address)
    } else {
        Err(errors::GetRegisterKeyErr { status, message: String::from("error in get_register_signing_key") }.into())
    }
}

// wrapper function for getting the enclave public sign key (the one attached with produce_quote())
pub fn get_ethereum_address(eid: sgx_enclave_id_t) -> Result<[u8; 20], Error> {
    let mut address = [0u8; 20];
    let status = unsafe { ecall_get_ethereum_address(eid, &mut address) };
    if status == sgx_status_t::SGX_SUCCESS {
        Ok(address)
    } else {
        Err(errors::GetRegisterKeyErr { status, message: String::from("error in get_ethereum_address") }.into())
    }
}

/// wrapper function for creating a signature using the ethereum key
pub fn sign_ethereum(eid: sgx_enclave_id_t, to_sign: &[u8; 32]) -> Result<[u8; 65], Error> {
    let mut sig = [0u8; 65];
    let status = unsafe { ecall_sign_ethereum(eid,to_sign, &mut sig) };
    if status == sgx_status_t::SGX_SUCCESS {
        Ok(sig)
    } else {
        Err(errors::GetRegisterKeyErr { status, message: String::from("error in sign_ethereum") }.into())
    }
}

#[cfg(test)]
mod test {
    use crate::esgx::general::init_enclave_wrapper;
    use enigma_tools_u::{
        attestation_service::{self, service::AttestationService},
        esgx::equote::retry_quote,
    };

    // isans SPID = "3DDB338BD52EE314B01F1E4E1E84E8AA"
    // victors spid = 68A8730E9ABF1829EA3F7A66321E84D0
    const SPID: &str = "B0335FD3BC1CCA8F804EB98A6420592D"; // Elichai's SPID

    #[test]
    fn test_produce_quote() {
        // initiate the enclave
        let enclave = init_enclave_wrapper().unwrap();
        // produce a quote

        let tested_encoded_quote = match retry_quote(enclave.geteid(), &SPID, 18) {
            Ok(encoded_quote) => encoded_quote,
            Err(e) => {
                println!("[-] Produce quote Err {}, {}", e.as_fail(), e.backtrace());
                assert_eq!(0, 1);
                return;
            }
        };
        println!("-------------------------");
        println!("{}", tested_encoded_quote);
        println!("-------------------------");
        enclave.destroy();
        assert!(!tested_encoded_quote.is_empty());
        // assert_eq!(real_encoded_quote, tested_encoded_quote);
    }

    #[test]
    fn test_produce_and_verify_qoute() {
        let enclave = init_enclave_wrapper().unwrap();
        let quote = retry_quote(enclave.geteid(), &SPID, 18).unwrap();
        let service = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let as_response = service.get_report(quote).unwrap();

        assert!(as_response.result.verify_report().unwrap());
    }

    #[test]
    fn test_signing_key_against_quote() {
        let enclave = init_enclave_wrapper().unwrap();
        let quote = retry_quote(enclave.geteid(), &SPID, 18).unwrap();
        let service = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let as_response = service.get_report(quote).unwrap();
        assert!(as_response.result.verify_report().unwrap());
        let key = super::get_register_signing_address(enclave.geteid()).unwrap();
        let quote = as_response.get_quote().unwrap();
        assert_eq!(key, &quote.report_body.report_data[..20]);
    }
}
