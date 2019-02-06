use byteorder::{BigEndian, WriteBytesExt};
use crate::db::{CRUDInterface, DeltaKey, P2PCalls, ResultType, ResultTypeVec, Stype, DB};
use crate::esgx::general;
use enigma_tools_u::common_u::LockExpectMutex;
use enigma_crypto::hash::Sha256;
use enigma_types::{Hash256, ContractAddress, EnclaveReturn, RawPointer, traits::SliceCPtr};
use lru_cache::LruCache;
use std::sync::Mutex;
use std::{mem, ptr, slice};

lazy_static! { static ref DELTAS_CACHE: Mutex<LruCache<Hash256, Vec<Vec<u8>>>> = Mutex::new(LruCache::new(500)); }

#[no_mangle]
pub unsafe extern "C" fn ocall_get_home(output: *mut u8, result_len: &mut usize) {
    let path = general::storage_dir();
    let path_str = path.to_str().unwrap();
    ptr::copy_nonoverlapping(path_str.as_c_ptr(), output, path_str.len());
    *result_len = path_str.len();
}

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
            println!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            EnclaveReturn::OcallDBError
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_new_delta(db_ptr: *const RawPointer,
                                         enc_delta: *const u8, delta_len: usize,
                                         contract_id: &ContractAddress, _delta_index: *const u32) -> EnclaveReturn {
    let delta_index = ptr::read(_delta_index);
    let encrypted_delta = slice::from_raw_parts(enc_delta, delta_len);
    let key = DeltaKey::new(*contract_id, Stype::Delta(delta_index));
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
            println!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            EnclaveReturn::OcallDBError
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
    ptr as u64
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
            cache_id.write_uint::<BigEndian>(state_len as u64, mem::size_of_val(&state_len)).unwrap();
            DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), vec![state]);
            EnclaveReturn::Success
        }
        Err(_) => EnclaveReturn::OcallDBError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_get_state(db_ptr: *const RawPointer, addr: &ContractAddress, state_ptr: *mut u8, state_size: usize) -> EnclaveReturn {
    let mut cache_id = addr.to_vec();
    cache_id.write_uint::<BigEndian>(state_size as u64, mem::size_of_val(&state_size)).unwrap();

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
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();

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
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();

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
                        println!("res: {:?}", res);
                        enigma_types::write_ptr(&res[..], res_ptr, res_len);
                        EnclaveReturn::Success
                    }
                },
                Err(_) => EnclaveReturn::OcallDBError,
            }
        }
    }
}

fn get_deltas(db: &mut DB, addr: ContractAddress, start: u32, end: u32) -> ResultTypeVec<(DeltaKey, Vec<u8>)> {
    let key_start = DeltaKey::new(addr, Stype::Delta(start));
    let key_end = DeltaKey::new(addr, Stype::Delta(end));


    db.get_deltas(key_start, key_end)
}
