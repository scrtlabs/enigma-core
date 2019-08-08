use core::clone::Clone;

use enigma_tools_m::keeper_types::{decode, EPOCH_CAP, InputWorkerParams, RawEncodable};
use enigma_tools_m::utils::LockExpectMutex;
use ethereum_types::{H256, U256};
use rustc_hex::ToHex;
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::{collections::HashMap, path, str, string::String, sync::SgxMutex};

use enigma_crypto::hash::Keccak256;
use enigma_tools_t::{
    common::{
        errors_t::{
            EnclaveError::{self, *},
            EnclaveSystemError::*,
        },
    },
    document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage},
};
use enigma_types::{ContractAddress, Hash256};
use epoch_keeper_t::epoch_t::{Epoch, EpochMarker, EpochNonce};
use ocalls_t;

use crate::SIGNING_KEY;

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

fn get_epoch_marker_path(nonce: U256) -> path::PathBuf {
    let path = format!("epoch-marker-{:?}.sealed", nonce);
    get_epoch_root_path().join(&path)
}

/// Get the epoch marker value of H(`Epoch`)
fn get_epoch_marker(nonce: U256) -> Result<Option<Hash256>, EnclaveError> {
    let path = get_epoch_marker_path(nonce);
    if !is_document(&path) {
        debug_println!("Sealed epoch marker not found in path: {:?}", path);
        return Ok(None);
    }
    debug_println!("Unsealing epoch marker: {:?}", path);
    let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
    load_sealed_document(&path, &mut sealed_log_out)?;
    let doc = SealedDocumentStorage::<EpochMarker>::unseal(&mut sealed_log_out)?;
    let marker: Option<Hash256> = match doc {
        Some(doc) => {
            let marker = doc.data;
            debug_println!("Found epoch marker: {:?}", marker.to_vec());
            let mut nonce: [u8; 32] = [0; 32];
            nonce.copy_from_slice(&marker[..32]);
            let mut hash: [u8; 32] = [0; 32];
            hash.copy_from_slice(&marker[32..]);
            debug_println!("Split marker into nonce / hash: {:?} {:?}", nonce.to_vec(), hash.to_vec());
            Some(hash.into())
        }
        _ => {
            debug_println!("Sealed epoch marker is empty");
            return Err(SystemError(WorkerAuthError {
                err: format!("Failed to unseal epoch marker: {:?}", path),
            }));
        }
    };
    Ok(marker)
}

fn get_epoch_from_cache(epoch_map: &HashMap<U256, Epoch>, nonce: U256) -> Result<Epoch, EnclaveError> {
    match epoch_map.get(&nonce) {
        Some(epoch) => Ok(epoch.clone()),
        None => Err(SystemError(WorkerAuthError { err: format!("Epoch nonce {:?} not found in cache.", nonce) })),
    }
}

/// Store the new `Epoch` as a sealed marker
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
    let marker_path = get_epoch_marker_path(nonce);
    save_sealed_document(&marker_path, &sealed_log_in)?;
    debug_println!("Sealed the epoch marker: {:?}", marker_path);
    Ok(())
}

pub(crate) fn ecall_set_worker_params_internal(worker_params_rlp: &[u8], seed_in: &[u8; 32], nonce_in: &[u8; 32],
                                               rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32],
                                               sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let worker_params: InputWorkerParams = decode(worker_params_rlp);
    const EMPTY_SLICE: [u8; 32] = [0; 32];
    let mut existing_epoch: Option<Epoch> = None;
    // If the seed input is not an empty slice, recover an `Epoch` from the sealed marker
    // Verifying the seed only because a nonce input of 0 is also an empty slice
    if seed_in != &EMPTY_SLICE {
        let seed = U256::from(seed_in);
        let nonce = U256::from(nonce_in);
        // Get the epoch marker values (nonce + H(`Epoch`) fr
        if let Some(marker_hash) = get_epoch_marker(nonce)? {
            let worker_params = worker_params.clone();
            let epoch = Epoch { nonce, seed, worker_params };
            debug_println!("Verifying epoch: {:?}", epoch);
            let hash = epoch.raw_encode().keccak256();
            if hash != marker_hash {
                return Err(SystemError(WorkerAuthError {
                    err: format!("Given epoch parameters {:?} do not match the marker's epoch hash {:?}", nonce, marker_hash),
                }));
            }
            debug_println!("Epoch verified against the marker successfully");
            existing_epoch = Some(epoch);
        } else {
            return Err(SystemError(WorkerAuthError {
                err: format!("Epoch marker requested but not found for nonce {:?}", nonce),
            }));
        }
    }
    let mut guard = EPOCH.lock_expect("Epoch");
    // If no seed/nonce inputs were provided, create a new epoch
    let epoch = match existing_epoch {
        Some(epoch) => epoch,
        None => {
            // If the `Epoch` cache is not empty, increment the last nonce that exists in the hashmap by 1
            let nonce = match guard.keys().max() {
                Some(nonce) => nonce + 1,
                None => INIT_NONCE.into(),
            };
            debug_println!("Creating new epoch with nonce {:?}", nonce);
            *nonce_out = EpochNonce::from(nonce);
            rsgx_read_rand(&mut rand_out[..])?;
            let seed = U256::from(rand_out.as_ref());
            let epoch = Epoch { nonce, seed, worker_params };
            debug_println!("Generated random seed: {:?}", seed);
            store_epoch(epoch.clone())?;
            epoch
        }
    };
    debug_println!("Inserting epoch: {:?} in cache", epoch);
    // Removing the first item (lower nonce) from the cache if capacity is reached
    if guard.len() == EPOCH_CAP {
        // Safe to unwrap because we just verified the size of the `HashMap`
        // Cloning because I couldn't mutably borrow the key enough to satisfy the borrow checker
        let key = guard.keys().min().unwrap().clone();
        if let Some(removed_epoch) = guard.remove(&key) {
           debug_println!("Cache reached its capacity of {}, removed first epoch: {:?}", EPOCH_CAP, removed_epoch);
        }
    }
    // Add the `Epoch` to the epoch cache regardless of weather it was created or recovered from a sealed marker
    match guard.insert(epoch.nonce.clone(), epoch.clone()) {
        Some(prev) => debug_println!("New epoch stored successfully"),
        None => debug_println!("Initial epoch stored successfully"),
    }
    let msg = epoch.raw_encode();
    *sig_out = SIGNING_KEY.sign(&msg)?;
    debug_println!("Signed the message : 0x{}", msg.to_hex::<String>());
    Ok(())
}

pub(crate) fn ecall_get_epoch_worker_internal(sc_addr: ContractAddress, nonce: U256) -> Result<[u8; 20], EnclaveError> {
    let guard = EPOCH.lock_expect("Epoch");
    let epoch = get_epoch_from_cache(&guard, nonce)?;
    debug_println!("Running worker selection using Epoch: {:?}", epoch);
    let worker = epoch.get_selected_worker(sc_addr)?;
    debug_println!("Found selected worker: {:?}", worker);
    Ok(worker.0)
}

pub mod tests {
    use ethereum_types::{H160, U256};
    use rustc_hex::FromHex;
    use std::prelude::v1::Vec;
    use std::string::String;

    use super::*;

    // noinspection RsTypeCheck
    pub fn test_get_epoch_worker_internal() {
        let worker_params = InputWorkerParams {
            block_number: U256::from(1),
            workers: vec![H160::from(0), H160::from(1), H160::from(2), H160::from(3)],
            stakes: vec![U256::from(1), U256::from(1), U256::from(1), U256::from(1)],
        };
        let epoch = Epoch { nonce: U256::from(0), seed: U256::from(1), worker_params };
        let sc_addr = ContractAddress::from([1u8; 32]);
        let worker = epoch.get_selected_worker(sc_addr).unwrap();
    }

    pub fn test_create_epoch_image() {
        let reference_image_hex1 = String::from("0000000000000020000000000000000000000000000000000000000000000000000000000001622a0000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let worker_params1 = InputWorkerParams {
            block_number: U256::from(1),
            workers: vec![],
            stakes: vec![],
        };
        let epoch1 = Epoch { nonce: U256::from(0), seed: U256::from(90666), worker_params: worker_params1 };
        let image1 = epoch1.raw_encode();
        assert_eq!(image1, reference_image_hex1.from_hex::<Vec<u8>>().unwrap());

        let reference_image_hex2 = String::from("0000000000000020000000000000000000000000000000000000000000000000000000000000b64500000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000700000000000000149c1ac1fca5a7bff4fb7e359a9e0e40c2a430e7b30000000000000014151d1caa3e3a1c0b31d1fd64b6d520ef610bf99c00000000000000141bece83ac1a195cdf6ba8f99dfb9b0a7c05b4b9b0000000000000014be49a926dc3e39173d85c80b87b78cd3971cb16f0000000000000014903cd5c2a29f6c319f58c7f9c6ad6903a13660e200000000000000148f7bfd7185add79c44e45be3bf1f72238ef5b3200000000000000014fead1eb428bf84b61ccbaadb2d3e003e968c28470000000000000007000000000000002000000000000000000000000000000000000000000000000000000014f46b0400000000000000002000000000000000000000000000000000000000000000000000000002540be4000000000000000020000000000000000000000000000000000000000000000000000000003b9aca0000000000000000200000000000000000000000000000000000000000000000000000000077359400000000000000002000000000000000000000000000000000000000000000000000000002540be400000000000000002000000000000000000000000000000000000000000000000000000004a817c800000000000000002000000000000000000000000000000000000000000000000000000000ee6b2800");
        let workers: Vec<[u8; 20]> = vec![
            [156, 26, 193, 252, 165, 167, 191, 244, 251, 126, 53, 154, 158, 14, 64, 194, 164, 48, 231, 179],
            [21, 29, 28, 170, 62, 58, 28, 11, 49, 209, 253, 100, 182, 213, 32, 239, 97, 11, 249, 156],
            [27, 236, 232, 58, 193, 161, 149, 205, 246, 186, 143, 153, 223, 185, 176, 167, 192, 91, 75, 155],
            [190, 73, 169, 38, 220, 62, 57, 23, 61, 133, 200, 11, 135, 183, 140, 211, 151, 28, 177, 111],
            [144, 60, 213, 194, 162, 159, 108, 49, 159, 88, 199, 249, 198, 173, 105, 3, 161, 54, 96, 226],
            [143, 123, 253, 113, 133, 173, 215, 156, 68, 228, 91, 227, 191, 31, 114, 35, 142, 245, 179, 32],
            [254, 173, 30, 180, 40, 191, 132, 182, 28, 203, 170, 219, 45, 62, 0, 62, 150, 140, 40, 71],
        ];
        let stakes: Vec<u64> = vec![
            90000000000,
            10000000000,
            1000000000,
            2000000000,
            10000000000,
            20000000000,
            4000000000,
        ];
        let worker_params2 = InputWorkerParams {
            block_number: U256::from(1),
            workers: workers.into_iter().map(|a| H160(a)).collect(),
            stakes: stakes.into_iter().map(|s| U256::from(s.clone())).collect(),
        };
        let epoch2 = Epoch { nonce: U256::from(1), seed: U256::from(46661), worker_params: worker_params2 };
        let image2 = epoch2.raw_encode();
        assert_eq!(image2, reference_image_hex2.from_hex::<Vec<u8>>().unwrap());
    }
}
