use failure::Error;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use web3::types::{Bytes, U256};

use common_u::errors::EnclaveFailError;
use enigma_tools_u::web3_utils::provider_types::{ encode, EpochSeed, Encodable};
use enigma_tools_u::web3_utils::keeper_types_u::InputWorkerParams;
use enigma_types::EnclaveReturn;

extern {
    fn ecall_set_worker_params(eid: sgx_enclave_id_t, retval: &mut EnclaveReturn,
                               worker_params_rlp: *const u8, worker_params_rlp_len: usize,
                               rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32],
                               sig_out: &mut [u8; 65]) -> sgx_status_t;
}

/// Returns an EpochSeed object 32 bytes signed random seed and an incremented account nonce.
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let worker_params = web3.get_worker_params(block_number);
/// let sig = set_worker_params(enclave.geteid(), worker_params).unwrap();
/// ```
pub fn set_worker_params(eid: sgx_enclave_id_t, worker_params: InputWorkerParams) -> Result<EpochSeed, Error> {
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    let mut nonce_out: [u8; 32] = [0; 32];
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    // Serialize the receipt into RLP
    let worker_params_rlp = encode(&worker_params);
    let status = unsafe {
        ecall_set_worker_params(
            eid,
            &mut retval,
            worker_params_rlp.as_ptr() as *const u8,
            worker_params_rlp.len(),
            &mut rand_out,
            &mut nonce_out,
            &mut sig_out,
        )
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    Ok(EpochSeed {
        seed: U256::from_big_endian(&rand_out),
        nonce: U256::from_big_endian(&nonce_out),
        sig: Bytes(sig_out.to_vec())
    })
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use ethabi::Uint;
    use rustc_hex::ToHex;
    use sgx_urts::SgxEnclave;
    use web3::types::{Bytes, Address};
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

    pub(crate) fn set_mock_worker_params(eid: sgx_enclave_id_t) -> (EpochSeed) {
        let worker_params = InputWorkerParams{
            block_number: U256::from(1),
            workers: vec![Address::from("f25186B5081Ff5cE73482AD761DB0eB0d25abfBF")],
            stakes: vec![U256::from(1)]
        };
        set_worker_params(eid, worker_params).unwrap()
    }


    #[test]
    fn test_set_mock_worker_params() {
        let enclave = init_enclave();
        let epoch_seed = set_mock_worker_params(enclave.geteid());
        println!("Got epoch seed params: {:?}", epoch_seed);
        assert_eq!(epoch_seed.nonce, Uint::from(0));

        enclave.destroy();
    }
}
