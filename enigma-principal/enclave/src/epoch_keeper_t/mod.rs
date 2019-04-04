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
use enigma_types::ContractAddress;
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

fn get_epoch(epoch_map: &HashMap<U256, Epoch>, block_number: Option<U256>) -> Result<Option<Epoch>, EnclaveError> {
    println!("Getting epoch for block number: {:?}", block_number);
    if block_number.is_some() {
        Err(SystemError(WorkerAuthError { err: "Epoch lookup by block number not implemented.".to_string() }))
    } else if epoch_map.is_empty() {
        println!("Epoch not found");
        let nonce_path = get_epoch_marker_path();
        if is_document(&nonce_path) {
            println!("Unsealing epoch nonce");
            let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
            load_sealed_document(&nonce_path, &mut sealed_log_out)?;
            let doc = SealedDocumentStorage::<EpochMarker>::unseal(&mut sealed_log_out)?;
            if let Some(doc) = doc {
                let marker = doc.data;
                println!("found epoch marker: {:?}", marker.to_vec());
                // TODO: unseal the epoch
            }
        }
        Ok(None)
    } else {
        // The epoch map cannot be empty here
        let nonce = epoch_map.keys().max().unwrap();
        let epoch: Epoch = epoch_map.get(nonce).unwrap().clone();
        Ok(Some(epoch))
    }
}

/// Creates new epoch both in the cache and as sealed documents
fn new_epoch(nonce_map: &mut HashMap<U256, Epoch>, worker_params: &InputWorkerParams,
             nonce: U256, seed: U256) -> Result<Epoch, EnclaveError> {
    let hash: [u8; 32] = rlpEncode(worker_params).keccak256().into();
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

    let epoch = Epoch { nonce, seed, worker_params: worker_params.clone() };
    // TODO: seal the epoch
    println!("Storing epoch: {:?}", epoch);
    match nonce_map.insert(nonce, epoch.clone()) {
        Some(prev) => println!("New epoch stored successfully, previous epoch: {:?}", prev),
        None => println!("Initial epoch stored successfully"),
    }
    Ok(epoch)
}

pub(crate) fn ecall_set_worker_params_internal(worker_params_rlp: &[u8], rand_out: &mut [u8; 32],
                                               nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let worker_params = decode(worker_params_rlp);
    let mut guard = EPOCH.lock_expect("Epoch");

    let nonce: U256 = get_epoch(&*guard, None)?.map_or_else(|| INIT_NONCE.into(), |_| guard.keys().max().unwrap() + 1);

    println!("Generated a nonce by incrementing the previous by 1 {:?}", nonce);
    *nonce_out = EpochNonce::from(nonce);

    rsgx_read_rand(&mut rand_out[..])?;

    let seed = U256::from(rand_out.as_ref());
    println!("Generated random seed: {:?}", seed);
    let epoch = new_epoch(&mut guard, &worker_params, nonce, seed)?;

    let msg = epoch.raw_encode();
    *sig_out = SIGNING_KEY.sign(&msg)?;
    println!("Signed the message : 0x{}", msg.to_hex());
    Ok(())
}

pub(crate) fn ecall_get_epoch_worker_internal(sc_addr: ContractAddress, block_number: Option<U256>) -> Result<[u8; 20], EnclaveError> {
    let guard = EPOCH.lock_expect("Epoch");
    let epoch = match get_epoch(&guard, block_number)? {
        Some(epoch) => epoch,
        None => {
            return Err(SystemError(WorkerAuthError {
                err: format!("No epoch found for block number (None == latest): {:?}", block_number),
            }));
        }
    };
    println!("Running worker selection using Epoch: {:?}", epoch);
    let worker = epoch.get_selected_worker(sc_addr)?;
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
