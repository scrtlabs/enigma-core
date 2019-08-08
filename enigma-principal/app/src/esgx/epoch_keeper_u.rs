use enigma_tools_m::keeper_types::InputWorkerParams;
use failure::Error;
use rustc_hex::ToHex;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use web3::types::{Bytes, H256, U256};

use common_u::errors::EnclaveFailError;
use enigma_types::{EnclaveReturn, traits::SliceCPtr};
use epoch_u::epoch_types::{encode, EpochState};

extern "C" {
    fn ecall_set_worker_params(
        eid: sgx_enclave_id_t, retval: &mut EnclaveReturn, worker_params_rlp: *const u8, worker_params_rlp_len: usize,
        seed_in: &[u8; 32], nonce_in: &[u8; 32],
        rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65],
    ) -> sgx_status_t;
}

/// Returns an EpochState object containing the 32 bytes signed random seed and an incremented account nonce.
/// If the `epoch_state` param is some, verify the corresponding sealed `Epoch` marker
/// Otherwise, create a new `Epoch`
///
/// # Arguments
/// * `eid` - The Enclave Id
/// * `worker_params` - The `InputWorkerParams` to store in an `Epoch`
/// * `epoch_state` - Optional, the existing `EpochState` to verify against sealed `Epoch` marker
///
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let result = self.contract.get_active_workers(block_number)?;
/// let worker_params: InputWorkerParams = InputWorkerParams { block_number, workers: result.0, stakes: result.1 };
/// let sig = set_worker_params(enclave.geteid(), worker_params, None).unwrap();
/// ```
#[logfn(DEBUG)]
pub fn set_or_verify_worker_params(eid: sgx_enclave_id_t, worker_params: &InputWorkerParams, epoch_state: Option<EpochState>) -> Result<EpochState, Error> {
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    println!("Evaluating nonce/seed based on EpochState: {:?}", epoch_state);
    let (nonce_in, seed_in) = match epoch_state.clone() {
        Some(e) => (H256::from(e.nonce).0, H256::from(e.seed).0),
        None => ([0; 32], [0; 32])
    };
    println!("Calling enclave set_worker_params with nonce/seed: {:?}/{:?}", nonce_in.to_vec().to_hex(), seed_in.to_vec().to_hex());
    let (mut nonce_out, mut rand_out) = ([0; 32], [0; 32]);
    let mut sig_out: [u8; 65] = [0; 65];
    // Serialize the InputWorkerParams into RLP
    let worker_params_rlp = encode(worker_params);
    let status = unsafe {
        ecall_set_worker_params(
            eid,
            &mut retval,
            worker_params_rlp.as_c_ptr() as *const u8,
            worker_params_rlp.len(),
            &seed_in,
            &nonce_in,
            &mut rand_out,
            &mut nonce_out,
            &mut sig_out,
        )
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    // If an `EpochState` was given and the ecall succeeded, it is considered verified
    // Otherwise, build a new `EpochState` from the parameters of the new epoch
    let epoch_state_out = match epoch_state {
        Some(epoch_state) => epoch_state,
        None => {
            let seed = U256::from_big_endian(&rand_out);
            let sig = Bytes(sig_out.to_vec());
            let nonce = U256::from_big_endian(&nonce_out);
            EpochState::new(seed, sig, nonce)
        }
    };
    Ok(epoch_state_out)
}

#[cfg(test)]
pub mod tests {
    use rustc_hex::{FromHex, ToHex};
    use web3::types::{Address, H160, H256};

    use esgx::general::init_enclave_wrapper;

    use super::*;

    pub fn get_worker_params(block_number: u64, workers: Vec<[u8; 20]>, stakes: Vec<u64>) -> InputWorkerParams {
        InputWorkerParams {
            block_number: U256::from(block_number),
            workers: workers.into_iter().map(|a| H160(a)).collect::<Vec<H160>>(),
            stakes: stakes.into_iter().map(|s| U256::from(s)).collect::<Vec<U256>>(),
        }
    }

    //TODO: Test error scenario with `set_mock_worker_params`

    #[test]
    fn test_set_mock_worker_params() {
        let enclave = init_enclave_wrapper().unwrap();
        let workers: Vec<[u8; 20]> = vec![
            [156, 26, 193, 252, 165, 167, 191, 244, 251, 126, 53, 154, 158, 14, 64, 194, 164, 48, 231, 179],
        ];
        let stakes: Vec<u64> = vec![90000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        let epoch_state = set_or_verify_worker_params(enclave.geteid(), &worker_params, None).unwrap();
        assert!(epoch_state.confirmed_state.is_none());
        enclave.destroy();
    }

    #[test]
    fn test_set_mock_worker_params_above_cap() {
        let enclave = init_enclave_wrapper().unwrap();
        let workers: Vec<[u8; 20]> = vec![
            [156, 26, 193, 252, 165, 167, 191, 244, 251, 126, 53, 154, 158, 14, 64, 194, 164, 48, 231, 179],
        ];
        let stakes: Vec<u64> = vec![90000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        for i in 0..5 {
            let epoch_state = set_or_verify_worker_params(enclave.geteid(), &worker_params, None).unwrap();
            assert!(epoch_state.confirmed_state.is_none());
        }
        enclave.destroy();
    }
}
