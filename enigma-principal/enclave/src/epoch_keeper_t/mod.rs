use crate::SIGNING_KEY;
use enigma_tools_m::keeper_types::{decode, rlpEncode, InputWorkerParams, RawEncodable};
use enigma_tools_t::{
    common::{
        errors_t::{
            EnclaveError::{self, *},
            EnclaveSystemError::*,
        },
        utils_t::LockExpectMutex,
        ToHex,
    },
    document_storage_t::{is_document, load_sealed_document, save_sealed_document, SealedDocumentStorage, SEAL_LOG_SIZE},
};
use enigma_types::{ContractAddress, Hash256};
use epoch_keeper_t::epoch_t::{Epoch, EpochMarker, EpochNonce};
use ethereum_types::{U256, H256};
use ocalls_t;
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::{collections::HashMap, path, str, string::ToString, sync::SgxMutex};
use enigma_crypto::hash::Keccak256;

pub mod epoch_t;

const INIT_NONCE: uint32_t = 0;
const EPOCH_DIR: &str = "epoch";

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
lazy_static! {
    pub static ref EPOCH: SgxMutex<HashMap<U256, Epoch>> = SgxMutex::new(HashMap::new());
}

/// The epoch root path is guaranteed to exist of the enclave was initialized
fn get_epoch_root_path() -> path::PathBuf {
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    path_buf.push(EPOCH_DIR);
    path_buf
}

fn get_epoch_marker_path() -> path::PathBuf { get_epoch_root_path().join("epoch-marker.sealed") }

fn get_epoch_marker(epoch_map: &HashMap<U256, Epoch>) -> Result<Option<(U256, Hash256)>, EnclaveError> {
    let path = get_epoch_marker_path();
    if !is_document(&path) {
        println!("Sealed epoch marker not found in path: {:?}", path);
        return Ok(None);
    }
    println!("Unsealing epoch marker: {:?}", path);
    let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
    load_sealed_document(&path, &mut sealed_log_out)?;
    let doc = SealedDocumentStorage::<EpochMarker>::unseal(&mut sealed_log_out)?;
    let marker: Option<(U256, Hash256)> = match doc {
        Some(doc) => {
            let marker = doc.data;
            println!("Found epoch marker: {:?}", marker.to_vec());
            let mut nonce: [u8; 32] = [0; 32];
            nonce.copy_from_slice(&marker[..32]);
            let mut hash: [u8; 32] = [0; 32];
            hash.copy_from_slice(&marker[32..]);
            println!("Split marker into nonce / hash: {:?} {:?}", nonce.to_vec(), hash.to_vec());
            Some((nonce.into(), hash.into()))
        }
        _ => {
            println!("Sealed epoch marker is empty");
            return Err(SystemError(WorkerAuthError {
                err: format!("Failed to unseal epoch marker: {:?}", path),
            }));
        }
    };
    Ok(marker)
}

fn get_current_epoch(epoch_map: &HashMap<U256, Epoch>) -> Result<Epoch, EnclaveError> {
    let epoch = match epoch_map.keys().max() {
        Some(nonce) => epoch_map.get(&nonce).unwrap().clone(),
        None => {
            return Err(SystemError(WorkerAuthError {
                err: format!("Epoch cache is empty"),
            }));
        }
    };
    Ok(epoch)
}

/// Creates new epoch both in the cache and as sealed documents
fn store_epoch(epoch: Epoch) -> Result<(), EnclaveError> {
    let hash: [u8; 32] = epoch.raw_encode().keccak256().into();
    let nonce = epoch.nonce.clone();
    let mut data = H256::from(nonce).0.to_vec();
    data.extend(hash.to_vec());
    let mut marker_doc: SealedDocumentStorage<EpochMarker> = SealedDocumentStorage {
        version: 0x1234, // TODO: what's this?
        data: [0; 64],
    };
    // Length of the slice guaranteed to be 64
    marker_doc.data.copy_from_slice(&data);
    let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
    marker_doc.seal(&mut sealed_log_in)?;
    // Save sealed_log to file
    let marker_path = get_epoch_marker_path();
    save_sealed_document(&marker_path, &sealed_log_in)?;
    println!("Sealed the epoch marker: {:?}", marker_path);
    Ok(())
}

pub(crate) fn ecall_set_worker_params_internal(worker_params_rlp: &[u8], seed_in: &[u8; 32], nonce_in: &[u8; 32],
                                               rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32],
                                               sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let worker_params: InputWorkerParams = decode(worker_params_rlp);
    let mut guard = EPOCH.lock_expect("Epoch");
    let marker = get_epoch_marker(&*guard)?;
    println!("Marker {:?} / raw seed {:?} / raw nonce {:?}", marker, seed_in.to_vec(), nonce_in.to_vec());
    const empty_slice: [u8; 32] = [0; 32];
    let existing_epoch = match marker {
        Some((marker_nonce, marker_hash)) if seed_in != &empty_slice => {
            println!("Verifying given parameters against the marker");
            let seed = U256::from(seed_in.as_ref());
            let nonce = U256::from(nonce_in.as_ref());
            let worker_params = worker_params.clone();
            let epoch = Epoch { nonce, seed, worker_params };
            println!("Verifying epoch: {:?}", epoch);
            let hash = epoch.raw_encode().keccak256();
            if hash != marker_hash {
                println!("Given epoch nonce {:?} do not match the marker {:?}: {:?}", nonce, marker_nonce, marker_hash);
                return Err(SystemError(WorkerAuthError {
                    err: format!("Given epoch parameters {:?} do not match the marker {:?}: {:?}", nonce, marker_nonce, marker_hash),
                }));
            }
            println!("Epoch verified against the marker successfully");
            Some(epoch)
        }
        None if seed_in != &empty_slice => {
            return Err(SystemError(WorkerAuthError {
                err: format!("Cannot verify given parameters without a sealed marker"),
            }));
        }
        _ => None
    };
    let epoch = match existing_epoch {
        Some(epoch) => epoch,
        None => {
            let nonce = match marker {
                Some((nonce, _)) => nonce + 1,
                None => INIT_NONCE.into(),
            };
            println!("Creating new epoch with nonce {:?}", nonce);
            *nonce_out = EpochNonce::from(nonce);
            rsgx_read_rand(&mut rand_out[..])?;
            let seed = U256::from(rand_out.as_ref());
            let epoch = Epoch { nonce, seed, worker_params };
            println!("Generated random seed: {:?}", seed);
            store_epoch(epoch.clone())?;
            epoch
        }
    };
    println!("Storing epoch in cache: {:?}", epoch);
    match guard.insert(epoch.nonce.clone(), epoch.clone()) {
        Some(prev) => println!("New epoch stored successfully, previous epoch: {:?}", prev),
        None => println!("Initial epoch stored successfully"),
    }
    let msg = epoch.raw_encode();
    *sig_out = SIGNING_KEY.sign(&msg)?;
    println!("Signed the message : 0x{}", msg.to_hex());
    Ok(())
}

pub(crate) fn ecall_get_epoch_worker_internal(sc_addr: ContractAddress, block_number: Option<U256>) -> Result<[u8; 20], EnclaveError> {
    let guard = EPOCH.lock_expect("Epoch");
    let epoch = get_current_epoch(&guard)?;
    println!("Running worker selection using Epoch: {:?}", epoch);
    let worker = epoch.get_selected_worker(sc_addr)?;
    println!("Found selected worker: {:?}", worker);
    Ok(worker.0)
}

pub mod tests {
    use super::*;
    use ethereum_types::{H160, U256};

    // noinspection RsTypeCheck
    pub fn test_get_epoch_worker_internal() {
        let worker_params = InputWorkerParams {
            block_number: U256::from(1),
            workers: vec![H160::from(0), H160::from(1), H160::from(2), H160::from(3)],
            stakes: vec![U256::from(1), U256::from(1), U256::from(1), U256::from(1)],
        };
        let epoch = Epoch { nonce: U256::from(0), seed: U256::from(1), worker_params };
        println!("The epoch: {:?}", epoch);
        let sc_addr = ContractAddress::from([1u8; 32]);
        let worker = epoch.get_selected_worker(sc_addr).unwrap();
        println!("The selected workers: {:?}", worker);
    }
}
