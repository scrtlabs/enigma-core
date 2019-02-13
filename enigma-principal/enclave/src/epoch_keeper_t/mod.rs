use ethabi::{Address, Hash, Token, Uint};
use ethereum_types::H256;
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::str;
use std::string::ToString;
use std::sync::SgxMutex;
use std::sync::SgxMutexGuard;
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::eth_tools_t::epoch_t::Epoch;
use enigma_tools_t::eth_tools_t::keeper_types_t::{decode, InputWorkerParams};

use crate::SIGNINING_KEY;

const INIT_NONCE: uint32_t = 0;
const EPOCH_DIR: &str = "epoch";

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
// TODO: Seal / unseal
lazy_static! { pub static ref EPOCH: SgxMutex< HashMap<Uint, Epoch >> = SgxMutex::new(HashMap::new()); }

fn get_max_nonce(guard: &SgxMutexGuard<HashMap<Uint, Epoch, RandomState>>) -> Uint {
    guard.keys().max().unwrap().clone()
}

fn get_epoch(guard: &SgxMutexGuard<HashMap<Uint, Epoch, RandomState>>, block_number: Option<Uint>) -> Result<Option<Epoch>, EnclaveError> {
    println!("Getting epoch for block number: {:?}", block_number);
    if block_number.is_some() {
        return Err(EnclaveError::WorkerAuthError {
            err: "Epoch lookup by block number not implemented.".to_string(),
        });
    }
    if guard.is_empty() {
        println!("Epoch not found");
        return Ok(None);
    }
    let nonce = get_max_nonce(&guard);
    let epoch: Epoch = guard.get(&nonce).unwrap().clone();
    Ok(Some(epoch))
}

pub(crate) fn ecall_set_worker_params_internal(worker_params_rlp: &[u8], rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let receipt: InputWorkerParams = decode(worker_params_rlp);

    println!("Successfully decoded RLP objects");
    let mut guard = EPOCH.lock_expect("Epoch");
    let previous_epoch = get_epoch(&guard, None)?;
    let nonce: Uint = match previous_epoch {
        Some(_) => guard.keys().max().unwrap() + 1,
        None => Uint::from(INIT_NONCE),
    };
    println!("Generated a nonce by incrementing the previous by 1 {:?}", nonce);
    let nonce_bytes: [u8; 32] = nonce.into();
    nonce_out.copy_from_slice(&nonce_bytes[..]);

    // TODO: Check if needs to check the random is within the curve.
    rsgx_read_rand(&mut rand_out[..])?;
    // TODO: Sign on all the input worker params
    let sig = SIGNINING_KEY.sign(&rand_out[..])?;
    sig_out.copy_from_slice(&sig[..]);

    let seed_token = Token::Uint(rand_out[..].into());
    let seed = seed_token.to_uint().unwrap();
    let new_epoch = Epoch::new(receipt, nonce, seed)?;
    println!("Storing epoch: {:?}", new_epoch);
    match guard.insert(nonce, new_epoch) {
        Some(prev) => println!("New epoch stored successfully, previous epoch: {:?}", prev),
        None => println!("Initial epoch stored successfully"),
    }
    Ok(())
}

pub(crate) fn ecall_get_epoch_workers_internal(sc_addr: Hash, block_number: Option<Uint>) -> Result<(Vec<Address>), EnclaveError> {
    let guard = EPOCH.lock_expect("Epoch");
    let epoch = match get_epoch(&guard, block_number)? {
        Some(epoch) => epoch,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: format!("No epoch found for block number (None == latest): {:?}", block_number),
            });
        }
    };
    println!("Running worker selection using Epoch: {:?}", epoch);
    let workers = epoch.get_selected_workers(sc_addr, None)?;
    Ok(workers)
}

pub mod tests {
    use super::*;
    use ethereum_types::{U256, H160};

    //noinspection RsTypeCheck
    pub fn test_get_epoch_workers_internal() {
        let epoch = Epoch {
            block_number: U256::from(1),
            workers: vec![H160::from(0), H160::from(1), H160::from(2), H160::from(3)],
            balances: vec![U256::from(1), U256::from(1), U256::from(1), U256::from(1)],
            nonce: U256::from(0),
            seed: U256::from(1),
        };
        println!("The epoch: {:?}", epoch);
        let sc_addr = H256::from(1);
        let workers = epoch.get_selected_workers(sc_addr, None).unwrap();
        println!("The selected workers: {:?}", workers);
    }
}
