use failure::Error;
// general
//sgx
use sgx_types::{uint32_t, uint8_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use ethabi::{
    RawLog, ParamType, Hash, Event, EventParam, Token, encode, decode,
};
use web3::types::{H256, BlockHeader, Log};
use web3::contract::tokens::Tokenizable;

use enigma_tools_u;
use enigma_tools_u::attestation_service::constants;
use enigma_tools_u::attestation_service::service;

extern {
    fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t,
                             rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t;

    fn ecall_set_worker_params(eid: sgx_enclave_id_t, retval: &mut sgx_status_t,
                               receipt_tokens: *const u8, receipt_tokens_len: usize,
                               sig_out: &mut [u8; 65]) -> sgx_status_t;

    fn ecall_get_enc_state_keys(eid: sgx_enclave_id_t, retval: &mut sgx_status_t,
                                enc_msg: *const u8, enc_msg_len: usize,
                                sig: &[u8; 65],
                                enc_response_out: *mut u8, enc_response_len_out: &mut usize,
                                sig_out: &mut [u8; 65]) -> sgx_status_t;
}

pub fn generate_epoch_seed(eid: sgx_enclave_id_t) -> ([u8; 32], [u8; 65]) {
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    let result = unsafe {
        ecall_get_random_seed(eid, &mut retval, &mut rand_out, &mut sig_out)
    };
    assert_eq!(result, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (rand_out, sig_out)
}

pub fn set_worker_params(eid: sgx_enclave_id_t, log: Log, receipt_hashes: Option<Vec<H256>>, block_header: Option<BlockHeader>) -> ([u8; 65]) {
    // Serialize the receipt into an array of tokens
    let receipt: Vec<Token> = vec![
        Tokenizable::into_token(log.address),
        Tokenizable::into_token(log.topics),
        Token::Bytes(log.data.0),
    ];
    println!("The receipt tokens: {:?}", receipt);
    let receipt_tokens = encode(&receipt);
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    let result = unsafe {
        ecall_set_worker_params(
            eid,
            &mut retval,
            receipt_tokens.as_ptr() as *const u8,
            receipt_tokens.len(),
            &mut sig_out,
        )
    };
    assert_eq!(result, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (sig_out)
}

const MAX_ENC_RESPONSE_LEN: usize = 100_000;

pub fn get_enc_state_keys(eid: sgx_enclave_id_t, enc_msg: Vec<u8>, sig: [u8; 65]) -> (Vec<u8>, [u8; 65]) {
    let mut sig_out: [u8; 65] = [0; 65];
    let mut enc_response = vec![0u8; MAX_ENC_RESPONSE_LEN];
    let enc_response_slice = enc_response.as_mut_slice();
    let mut enc_response_len_out: usize = 0;
    let mut retval = sgx_status_t::default();

    println!("calling ecall_get_enc_state_keys with encoded message: {:?}", enc_msg);
    let response = unsafe {
        ecall_get_enc_state_keys(
            eid,
            &mut retval,
            enc_msg.as_ptr() as *const u8,
            enc_msg.len(),
            &sig,
            enc_response_slice.as_mut_ptr() as *mut u8,
            &mut enc_response_len_out,
            &mut sig_out,
        )
    };
    assert_eq!(response, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    println!("got encrypted state keys: {:?}", response);
    let enc_response_out = enc_response_slice[0..enc_response_len_out].iter().cloned().collect();
    (enc_response_out, sig_out)
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use std::prelude::v1::Vec;

    use rustc_hex::FromHex;
    use rustc_hex::ToHex;
    use sgx_urts::SgxEnclave;
    use tiny_keccak::Keccak;
    use web3::types::Bytes;

    use esgx;
    use esgx::random_u::get_signed_random;
    use ethabi::{Uint, Address};
    use ethabi::token::{Tokenizer, LenientTokenizer};
    use serde_json as ser;
    use super::*;

    fn init_enclave() -> SgxEnclave {
        let enclave = match esgx::general::init_enclave_wrapper() {
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

    pub(crate) fn set_mock_worker_params(eid: sgx_enclave_id_t) -> ([u8; 65]) {
        // Using test values from here: https://github.com/paritytech/ethabi/blob/master/ethabi/src/event.rs
        let event = Event {
            name: "WorkersParameterized".to_string(),
            inputs: vec![EventParam {
                name: "seed".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "blockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "workers".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                indexed: false,
            }, EventParam {
                name: "balances".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                indexed: false,
            }],
            anonymous: false,
        };
        let mut data: Vec<Token> = vec![
            LenientTokenizer::tokenize(&ParamType::Uint(256), "1").unwrap(),
            LenientTokenizer::tokenize(&ParamType::Uint(256), "100").unwrap(),
            Token::Array(
                LenientTokenizer::tokenize_array(
                    "[44301ca99939396a58c317b2e44df6a556fa95ae]",
                    &ParamType::Address,
                ).unwrap()
            ),
            Token::Array(
                LenientTokenizer::tokenize_array(
                    "[1000]",
                    &ParamType::Uint(256),
                ).unwrap()
            ),
        ];
        let log = Log {
            address: 1.into(),
            topics: vec![
                event.signature(),
            ],
            data: Bytes(encode(&data)),
            block_hash: Some(2.into()),
            block_number: Some(1.into()),
            transaction_hash: Some(3.into()),
            transaction_index: Some(0.into()),
            log_index: Some(0.into()),
            transaction_log_index: Some(0.into()),
            log_type: Some("mined".into()),
            removed: None,
        };
        return set_worker_params(eid, log, None, None);
    }

    #[test]
    fn test_set_worker_params() {
        let enclave = init_enclave();
        generate_epoch_seed(enclave.geteid());
        generate_epoch_seed(enclave.geteid());
        let sig = set_mock_worker_params(enclave.geteid());
        println!("got the data signature");
        enclave.destroy();
    }

    #[test]
    fn test_get_state_key() {
        let enclave = init_enclave();
        generate_epoch_seed(enclave.geteid());
        generate_epoch_seed(enclave.geteid());
        set_mock_worker_params(enclave.geteid());

        // From the km_primitives uint tests
        let request = "84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda".from_hex().unwrap();
        let sig = "43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c".from_hex().unwrap();
        println!("The mock request: {:?}", request);
        println!("The mock sig: {:?}", sig);

        let mut sig_slice: [u8; 65] = [0; 65];
        sig_slice.copy_from_slice(&sig[..]);
        println!("The sig slice: {:?}", sig_slice.to_vec());
        let (enc_result, sig) = get_enc_state_keys(enclave.geteid(), request, sig_slice);
        enclave.destroy();
    }
}
