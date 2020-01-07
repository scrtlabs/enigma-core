#![allow(unused_attributes)]
use crate::db::{CRUDInterface, DeltaKey, P2PCalls, ResultType, ResultTypeVec, Stype, DB};
use enigma_tools_m::utils::LockExpectMutex;
use enigma_crypto::hash::Sha256;
use enigma_types::{ContractAddress, EnclaveReturn, Hash256, RawPointer};
use lru_cache::LruCache;
use std::sync::Mutex;
use std::{ptr, slice};
use common_u::errors;

lazy_static! { static ref DELTAS_CACHE: Mutex<LruCache<Hash256, Vec<Vec<u8>>>> = Mutex::new(LruCache::new(500)); }


#[no_mangle]
pub unsafe extern "C" fn ocall_update_state(db_ptr: *const RawPointer, id: &ContractAddress, enc_state: *const u8, state_len: usize) -> EnclaveReturn {
    let encrypted_state = slice::from_raw_parts(enc_state, state_len);
    let key = DeltaKey::new(*id, Stype::State);

    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };
    match db.force_update(&key, encrypted_state) {
        Ok(_) => EnclaveReturn::Success,
        Err(e) => {
            error!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            EnclaveReturn::OcallDBError
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn ocall_new_delta(db_ptr: *const RawPointer,
                                         enc_delta: *const u8, delta_len: usize,
                                         contract_address: &ContractAddress, delta_index_: *const u32) -> EnclaveReturn {
    let delta_index = ptr::read(delta_index_);
    let encrypted_delta = slice::from_raw_parts(enc_delta, delta_len);
    let key = DeltaKey::new(*contract_address, Stype::Delta(delta_index));
    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };
    match db.force_update(&key, encrypted_delta) {
        Ok(_) => EnclaveReturn::Success,
        Err(e) => {
            error!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            EnclaveReturn::OcallDBError
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn ocall_get_state_size(db_ptr: *const RawPointer, addr: &ContractAddress, state_size: *mut usize) -> EnclaveReturn {
    let mut cache_id = addr.to_vec();
    let _state_key = DeltaKey::new(*addr, Stype::State);
    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };
    match db.read(&_state_key) {
        Ok(state) => {
            let state_len = state.len();
            *state_size = state_len;
            cache_id.extend_from_slice(&state_len.to_be_bytes());
            DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), vec![state]);
            EnclaveReturn::Success
        }
        Err(_) => EnclaveReturn::OcallDBError,
    }
}


#[no_mangle]
pub unsafe extern "C" fn ocall_get_state(db_ptr: *const RawPointer, addr: &ContractAddress, state_ptr: *mut u8, state_size: usize) -> EnclaveReturn {
    let mut cache_id = addr.to_vec();
    cache_id.extend_from_slice(&state_size.to_be_bytes());

    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };


    match DELTAS_CACHE.lock_expect("DeltaCache").remove(&cache_id.sha256()) {
        Some(state) => {
            enigma_types::write_ptr(&state[0][..], state_ptr, state_size);
            EnclaveReturn::Success
        }
        None => {
            let _state_key = DeltaKey::new(*addr, Stype::State);
            match db.read(&_state_key) {
                Ok(state) => {
                    enigma_types::write_ptr(&state, state_ptr, state_size);
                    EnclaveReturn::Success
                }
                Err(_) => EnclaveReturn::OcallDBError,
            }
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn ocall_get_deltas_sizes(db_ptr: *const RawPointer, addr: &ContractAddress,
                                                start: *const u32, end: *const u32,
                                                res_ptr: *mut usize, res_len: usize) -> EnclaveReturn {

    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };

    let len = (*end - *start) as usize;
    if len != res_len {
        return EnclaveReturn::OcallError;
    }
    let mut cache_id = addr.to_vec();
    cache_id.extend_from_slice(&(*start).to_be_bytes());
    cache_id.extend_from_slice(&(*end).to_be_bytes());

    let mut deltas_vec = Vec::with_capacity(len);
    let mut sizes = Vec::with_capacity(len);
    match get_deltas(db, *addr, *start, *end) {
        Ok(deltas_type) => match deltas_type {
            ResultType::None => return EnclaveReturn::OcallDBError,
            ResultType::Full(deltas) | ResultType::Partial(deltas) => {
                for delta in deltas {
                    sizes.push(delta.1.len());
                    deltas_vec.push(delta.1);
                }
            }
        },
        Err(_) => return EnclaveReturn::OcallDBError,
    };
    DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), deltas_vec);
    enigma_types::write_ptr(&sizes, res_ptr, res_len);
    EnclaveReturn::Success
}


#[no_mangle]
pub unsafe extern "C" fn ocall_get_deltas(db_ptr: *const RawPointer, addr: &ContractAddress,
                                             start: *const u32, end: *const u32,
                                             res_ptr: *mut u8, res_len: usize) -> EnclaveReturn {
    let mut cache_id = addr.to_vec();
    cache_id.extend_from_slice(&(*start).to_be_bytes());
    cache_id.extend_from_slice(&(*end).to_be_bytes());

    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };


    match DELTAS_CACHE.lock_expect("DeltaCache").remove(&cache_id.sha256()) {
        Some(deltas_vec) => {
            // The results here are flatten to one big array.
            // The Enclave needs to separate them back to the original.
            let res = deltas_vec.into_iter().flatten().collect::<Vec<u8>>();
            enigma_types::write_ptr(&res[..], res_ptr, res_len);
            EnclaveReturn::Success
        }
        None => {
            // If the data doesn't exist in the cache I need to pull it from the DB
            match get_deltas(db, *addr, *start, *end) {
                Ok(deltas_type) => match deltas_type {
                    ResultType::None => EnclaveReturn::OcallDBError,
                    ResultType::Full(deltas) | ResultType::Partial(deltas) => {
                        let res = deltas.iter().map(|(_, val)| val.clone()).flatten().collect::<Vec<u8>>();
                        enigma_types::write_ptr(&res[..], res_ptr, res_len);
                        EnclaveReturn::Success
                    }
                },
                Err(_) => EnclaveReturn::OcallDBError,
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_remove_delta(db_ptr: *const RawPointer,
                                            contract_address: &ContractAddress, delta_index_: *const u32) -> EnclaveReturn {
    let delta_index = ptr::read(delta_index_);
    let key = DeltaKey::new(*contract_address, Stype::Delta(delta_index));
    let db: &mut DB = match (*db_ptr).get_mut_ref() {
        Ok(db) => db,
        Err(e) => {
            error!("{}", e);
            return EnclaveReturn::OcallDBError
        }
    };
    match db.delete(&key) {
        Ok(_) => EnclaveReturn::Success,
        Err(e) => {
            match errors::is_db_err_type(e) {
                Ok(_) =>  EnclaveReturn::Success,
                Err(e) => {
                    error!("Failed removing delta: {:?} since {:?}", &key, e);
                    EnclaveReturn::OcallDBError
                },
            }
        }
    }
}

fn get_deltas(db: &mut DB, addr: ContractAddress, start: u32, end: u32) -> ResultTypeVec<(DeltaKey, Vec<u8>)> {
    let key_start = DeltaKey::new(addr, Stype::Delta(start));
    let key_end = DeltaKey::new(addr, Stype::Delta(end));


    db.get_deltas(key_start, key_end)
}
