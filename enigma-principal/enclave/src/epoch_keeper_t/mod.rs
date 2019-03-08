use ethabi::{Address, Hash, Token, Uint};
use ethereum_types::H256;
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::path;
use std::str;
use std::string::ToString;
use std::sync::SgxMutex;
use std::sync::SgxMutexGuard;
use std::untrusted::fs;
use std::vec::Vec;

use enigma_crypto::hash::Keccak256;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::EthereumAddress;
use enigma_tools_t::common::ToHex;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage};
use epoch_keeper_t::epoch_t::{Epoch, EpochNonce};
use keys_keeper_t::keeper_types_t::{decode, InputWorkerParams, RawEncodable};
use ocalls_t;

use crate::SIGNING_KEY;

pub mod epoch_t;

const INIT_NONCE: uint32_t = 0;
const EPOCH_DIR: &str = "epoch";

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
lazy_static! { pub static ref EPOCH: SgxMutex< HashMap<Uint, Epoch >> = SgxMutex::new(HashMap::new()); }

/// The epoch root path is guaranteed to exist of the enclave was initialized
fn get_epoch_root_path() -> path::PathBuf {
    let mut path_buf = ocalls_t::get_home_path();
    path_buf.push(EPOCH_DIR);
    path_buf
}

fn get_document_path(nonce: &Uint) -> path::PathBuf {
    get_epoch_root_path().join(format!("{:?}.{}", nonce, "sealed"))
}

fn get_epoch_nonce_path() -> path::PathBuf {
    get_epoch_root_path().join("nonce.sealed")
}

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
        let nonce_path = get_epoch_nonce_path();
        if is_document(&nonce_path) {
            println!("Unsealing epoch nonce");
            let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
            load_sealed_document(&nonce_path, &mut sealed_log_out)?;
            let doc = SealedDocumentStorage::<EpochNonce>::unseal(&mut sealed_log_out)?;
            match doc {
                Some(doc) => {
                    let nonce = Some(doc.data);
                    println!("found epoch marker: {:?}", nonce);
                    //TODO: unseal the epoch
                }
                None => ()
            }
        }
        return Ok(None);
    }
    let nonce = get_max_nonce(&guard);
    let epoch: Epoch = guard.get(&nonce).unwrap().clone();
    Ok(Some(epoch))
}

/// Creates new epoch both in the cache and as sealed documents
fn new_epoch(guard: &mut SgxMutexGuard<HashMap<Uint, Epoch, RandomState>>, worker_params: &InputWorkerParams, nonce: &Uint, seed: &Uint) -> Result<Epoch, EnclaveError> {
    let mut marker_doc: SealedDocumentStorage<EpochNonce> = SealedDocumentStorage {
        version: 0x1234, //TODO: what's this?
        data: [0; 32],
    };
    let nonce_bytes: EpochNonce = nonce.clone().into();
    marker_doc.data.copy_from_slice(&nonce_bytes);
    let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
    marker_doc.seal(&mut sealed_log_in)?;
    // Save sealed_log to file
    let marker_path = get_epoch_nonce_path();
    save_sealed_document(&marker_path, &sealed_log_in)?;
    println!("Sealed the epoch marker: {:?}", marker_path);

    let epoch = Epoch {
        nonce: nonce.clone(),
        seed: seed.clone(),
        worker_params: worker_params.clone(),
    };
    //TODO: seal the epoch
    println!("Storing epoch: {:?}", epoch);
    match guard.insert(nonce.clone(), epoch.clone()) {
        Some(prev) => println!("New epoch stored successfully, previous epoch: {:?}", prev),
        None => println!("Initial epoch stored successfully"),
    }
    Ok(epoch)
}

pub(crate) fn ecall_set_worker_params_internal(worker_params_rlp: &[u8], rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let worker_params: InputWorkerParams = decode(worker_params_rlp);
    println!("Successfully decoded RLP worker parameters");

    let mut guard = EPOCH.lock_expect("Epoch");
    let previous_epoch = get_epoch(&guard, None)?;
    let nonce: Uint = match previous_epoch {
        Some(_) => guard.keys().max().unwrap() + 1,
        None => Uint::from(INIT_NONCE),
    };
    println!("Generated a nonce by incrementing the previous by 1 {:?}", nonce);
    let nonce_bytes: EpochNonce = nonce.into();
    nonce_out.copy_from_slice(&nonce_bytes[..]);

    // TODO: Check if needs to check the random is within the curve.
    rsgx_read_rand(&mut rand_out[..])?;
    let seed_token = Token::Uint(rand_out[..].into());
    let seed = seed_token.to_uint().unwrap();
    println!("Generated random seed: {:?}", seed);

    let epoch = new_epoch(&mut guard, &worker_params, &nonce, &seed)?;
    let msg = epoch.raw_encode()?;
    let hash = msg.keccak256();
    println!("Signing msg hash {} with signer address {}", hash.to_hex(), SIGNING_KEY.get_pubkey().address_string());
    let sig = SIGNING_KEY.sign(hash.as_ref())?;
    sig_out.copy_from_slice(&sig[..]);
    println!("Signed the message hash: 0x{}", hash.to_hex());
    Ok(())
}

pub(crate) fn ecall_get_epoch_worker_internal(sc_addr: Hash, block_number: Option<Uint>) -> Result<Address, EnclaveError> {
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
    let worker = epoch.get_selected_worker(sc_addr)?;
    Ok(worker)
}

pub mod tests {
    use ethereum_types::{H160, U256};

    use super::*;

    //noinspection RsTypeCheck
    pub fn test_get_epoch_workers_internal() {
        let worker_params = InputWorkerParams {
            block_number: U256::from(1),
            workers: vec![H160::from(0), H160::from(1), H160::from(2), H160::from(3)],
            stakes: vec![U256::from(1), U256::from(1), U256::from(1), U256::from(1)],
        };
        let epoch = Epoch {
            nonce: U256::from(0),
            seed: U256::from(1),
            worker_params,
        };
        println!("The epoch: {:?}", epoch);
        let sc_addr = H256::from(1);
        let workers = epoch.get_selected_worker(sc_addr).unwrap();
        println!("The selected workers: {:?}", workers);
    }
}
