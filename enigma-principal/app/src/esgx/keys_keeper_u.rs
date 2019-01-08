use failure::Error;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use web3::types::{BlockHeader, H256, Log};

use boot_network::keys_provider_http::{StateKeyRequest, StateKeyResponse, StringWrapper};
use common_u::errors::EnclaveFailError;
use enigma_types::EnclaveReturn;

extern {
    fn ecall_get_enc_state_keys(eid: sgx_enclave_id_t, retval: &mut EnclaveReturn,
                                enc_msg: *const u8, enc_msg_len: usize,
                                sig: &[u8; 65],
                                enc_response_out: *mut u8, enc_response_len_out: &mut usize,
                                sig_out: &mut [u8; 65]) -> sgx_status_t;
}

const MAX_ENC_RESPONSE_LEN: usize = 100_000;

pub fn get_enc_state_keys(eid: sgx_enclave_id_t, request: StateKeyRequest) -> Result<StateKeyResponse, Error> {
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    let mut sig_out: [u8; 65] = [0; 65];
    let mut enc_response = vec![0u8; MAX_ENC_RESPONSE_LEN];
    let enc_response_slice = enc_response.as_mut_slice();
    let mut enc_response_len_out: usize = 0;

    let enc_msg: Vec<u8> = request.request_message.into();
    let status = unsafe {
        ecall_get_enc_state_keys(
            eid,
            &mut retval,
            enc_msg.as_ptr() as *const u8,
            enc_msg.len(),
            &request.worker_sig.into(),
            enc_response_slice.as_mut_ptr() as *mut u8,
            &mut enc_response_len_out,
            &mut sig_out,
        )
    };
    if retval != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: retval, status}.into());
    }
    let enc_response_out: Vec<u8> = enc_response_slice[0..enc_response_len_out].iter().cloned().collect();
    Ok(StateKeyResponse {
        encrypted_response_message: StringWrapper::from(enc_response_out),
        sig: StringWrapper::from(sig_out),
    })
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use std::prelude::v1::Vec;
    use sgx_urts::SgxEnclave;

    use esgx::epoch_keeper_u::generate_epoch_seed;
    use esgx::epoch_keeper_u::tests::set_mock_worker_params;
    use esgx::general::init_enclave_wrapper;

    use super::*;

    fn init_enclave() -> SgxEnclave {
        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                panic!("[-] Init Enclave Failed {}!", x.as_str());
            }
        };
        enclave
    }

    #[test]
    fn test_get_state_key() {
        let enclave = init_enclave();
        generate_epoch_seed(enclave.geteid());
        generate_epoch_seed(enclave.geteid());
        set_mock_worker_params(enclave.geteid());

        // From the km_primitives uint tests
        let msg = StringWrapper("84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda".to_string());
        let sig = StringWrapper("43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c".to_string());
        println!("The mock message: {:?}", msg);
        println!("The mock sig: {:?}", sig);

        let request = StateKeyRequest { request_message: msg, worker_sig: sig };
        let response = get_enc_state_keys(enclave.geteid(), request).unwrap();
//        println!("Got response: {:?}", response);
        enclave.destroy();
    }
}
