use crate::km_u::ContractAddress;
use crate::db::dal::CRUDInterface;
use crate::db::{DeltaKey, Stype, DATABASE, P2PCalls, ResultType, ResultTypeVec};
use crate::esgx::general;
use enigma_tools_u::common_u::{LockExpectMutex, Sha256};
use byteorder::{BigEndian, WriteBytesExt};
use std::{slice,ptr, mem};
use lru_cache::LruCache;
use std::sync::Mutex;

lazy_static! { pub static ref DELTAS_CACHE: Mutex< LruCache<[u8; 32], Vec<Vec<u8>> >> = Mutex::new(LruCache::new(10)); }

#[no_mangle]
pub unsafe extern "C" fn ocall_get_home(output: *mut u8, result_len: &mut usize) {
    let path = general::storage_dir();
    let path_str = path.to_str().unwrap();
    ptr::copy_nonoverlapping(path_str.as_ptr(), output, path_str.len());
    *result_len = path_str.len();
}

#[no_mangle]
pub unsafe extern "C" fn ocall_update_state(id: &[u8; 32], enc_state: *const u8, state_len: usize) -> i8 {
    let encrypted_state = slice::from_raw_parts(enc_state, state_len);

    let key = DeltaKey::new(*id, Stype::State);

    match DATABASE.lock().expect("Database mutex is poison").force_update(&key, encrypted_state) {
        Ok(_) => (), // No Error
        Err(e) => {
            println!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            return 17; // according to errno.h and errno-base.h (maybe use https://docs.rs/nix/0.11.0/src/nix/errno.rs.html, or something else)
        }
    };
    //    println!("logging: saving state {:?} in {:?}", key, encrypted_state);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ocall_new_delta(enc_delta: *const u8, delta_len: usize, delta_hash: &[u8; 32],
                                         _delta_index: *const u32) -> i8 {
    let delta_index = ptr::read(_delta_index);
    let encrypted_delta = slice::from_raw_parts(enc_delta, delta_len);
    let key = DeltaKey::new(*delta_hash, Stype::Delta(delta_index));
    // TODO: How should we handle the already existing error?
    match DATABASE.lock().expect("Database mutex is poison").force_update(&key, encrypted_delta) {
        Ok(_) => (), // No Error
        Err(e) => {
            println!("Failed creating key in db: {:?} with: \"{}\" ", &key, &e);
            return 17; // according to errno.h and errno-base.h (maybe use https://docs.rs/nix/0.11.0/src/nix/errno.rs.html, or something else)
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
    ptr as u64
}

#[no_mangle]
pub unsafe extern "C" fn ocall_get_state_size(addr: &ContractAddress, state_size: *mut usize) -> i8 {

    let mut cache_id = addr.to_vec();
    let _state_key = DeltaKey::new(*addr, Stype::State);
    match DATABASE.lock_expect("Database").read(&_state_key) {
        Ok(state) => {
            let state_len = state.len();
            *state_size = state_len;
            cache_id.write_uint::<BigEndian>(state_len as u64, mem::size_of_val(&state_len)).unwrap();
            DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), vec![state]);
            0
        },
        Err(_) => 17
    }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_get_state(addr: &ContractAddress, state_ptr: *mut u8, state_size: usize) -> i8 {
    let mut cache_id = addr.to_vec();
    cache_id.write_uint::<BigEndian>(state_size as u64, mem::size_of_val(&state_size)).unwrap();
    match DELTAS_CACHE.lock_expect("DeltaCache").remove(&cache_id.sha256()) {
        Some(state) => {
            write_ptr(&state[0][..], state_ptr, state_size);
            0
        },
        None => {
            let _state_key = DeltaKey::new(*addr, Stype::State);
            match DATABASE.lock_expect("Database").read(&_state_key) {
                Ok(state) => {
                    write_ptr(&state, state_ptr, state_size);
                    0
                },
                Err(_) => 17,
            }
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn ocall_get_deltas_sizes(addr: &ContractAddress, start: *const u32, end: *const u32, res_ptr: *mut usize, res_len: usize) -> i8 {
    let len = (*end-*start) as usize;
    if len != res_len {
        return 29;
    }
    let mut cache_id = addr.to_vec();
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();

    let mut deltas_vec = Vec::with_capacity(len);
    let mut sizes = Vec::with_capacity(len);
    match get_deltas(*addr, *start, *end) {
       Ok(deltas_type) => {
           match deltas_type {
               ResultType::None => return 17,
               ResultType::Full(deltas) | ResultType::Partial(deltas) => {
                   for delta in deltas {
                       sizes.push(delta.1.len());
                       deltas_vec.push(delta.1);
                   }
               },
           }
       }
        Err(_) => return 17
    };
    DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), deltas_vec);
    write_ptr(&sizes, res_ptr, res_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ocall_get_deltas(addr: &ContractAddress, start: *const u32, end: *const u32, res_ptr: *mut u8, res_len: usize) -> i8 {
    let len = (*end-*start) as usize;

    let mut cache_id = addr.to_vec();
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();
    match DELTAS_CACHE.lock_expect("DeltaCache").remove(&cache_id.sha256()) {
        Some(deltas_vec) => {
            // The results here are flatten to one big array.
            // The Enclave needs to seperate them back to the original.
            let res = deltas_vec.into_iter().flatten().collect::<Vec<u8>>();
            write_ptr(&res[..], res_ptr, res_len);
        }
        None => { // If the data doesn't exist in the cache I need to pull it from the DB
            match get_deltas(*addr, *start, *end) {
                Ok(deltas_type) => {
                    match deltas_type {
                        ResultType::None => return 17,
                        ResultType::Full(deltas) | ResultType::Partial(deltas) => {
                            let res = deltas.iter().map(|(_, val)| val.clone()).flatten().collect::<Vec<u8>>();
                            println!("res: {:?}", res);
                            write_ptr(&res[..], res_ptr, res_len);

                        },
                    }
                }
                Err(_) => return 17
            };
        }
    }
    0
}


unsafe fn write_ptr<T>(src: &[T], dst: *mut T, count: usize) {
    if src.len() > count {
        unimplemented!()
    }
    ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
}

fn get_deltas(addr: ContractAddress, start: u32, end: u32) -> ResultTypeVec<(DeltaKey, Vec<u8>)> {
    let key_start = DeltaKey::new(addr, Stype::Delta(start));
    let key_end = DeltaKey::new(addr, Stype::Delta(end));

    DATABASE.lock_expect("Database").get_deltas(key_start, key_end)
}