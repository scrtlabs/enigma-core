use crate::km_u::ContractAddress;
use crate::db::dal::CRUDInterface;
use crate::db::{DeltaKey, Stype, DATABASE, P2PCalls};
use crate::esgx::general;
use enigma_tools_u::common_u::{LockExpectMutex, Sha256};
use byteorder::{BigEndian, WriteBytesExt};
use std::{slice,ptr};
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
pub unsafe extern "C" fn ocall_get_deltas_sizes(addr: &ContractAddress, start: *const u32, end: *const u32, res_ptr: *mut usize, res_len: usize) -> i8 {
    let len = (*end-*start) as usize;
    if len != res_len {
        return 29;
    }
    let mut cache_id = addr.to_vec();
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();

    let key_start = DeltaKey::new(addr.clone(), Stype::Delta(*start));
    let key_end = DeltaKey::new(*addr, Stype::Delta(*end));
    let mut deltas_vec = Vec::with_capacity(len);
    let mut sizes = Vec::with_capacity(len);
    let deltas = DATABASE.lock_expect("Database").get_deltas(&[(key_start, key_end)]);
    for delta in deltas {
        let  v = match delta {
            Ok(r) => r.1.clone(),
            Err(_) => Vec::new(),
        };
        sizes.push(v.len());
        deltas_vec.push(v);
    }
    DELTAS_CACHE.lock_expect("DeltaCache").insert(cache_id.sha256(), deltas_vec);
    ptr::copy_nonoverlapping(sizes.as_ptr(), res_ptr, len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ocall_get_deltas(addr: &ContractAddress, start: *const u32, end: *const u32, res_ptr: *mut u8, res_len: usize) -> i8 {
    let len = (*end-*start) as usize;
    if len != res_len {
        return 29;
    }

    let mut cache_id = addr.to_vec();
    cache_id.write_u32::<BigEndian>(*start).unwrap();
    cache_id.write_u32::<BigEndian>(*end).unwrap();
    match DELTAS_CACHE.lock_expect("DeltaCache").remove(&cache_id.sha256()) {
        Some(deltas_vec) => {
            // The results here are flatten to one big array.
            // The Enclave needs to seperate them back to the original.
            let res = deltas_vec.into_iter().flatten().collect::<Vec<u8>>();

            ptr::copy_nonoverlapping(res.as_ptr(), res_ptr, res.len());

        }
        None => { // If the data doesn't exist in the cache I need to pull it from the DB
            let key_start = DeltaKey::new(addr.clone(), Stype::Delta(*start));
            let key_end = DeltaKey::new(*addr, Stype::Delta(*end));
            let mut deltas_vec = Vec::with_capacity(len);

            let deltas = DATABASE.lock_expect("Database").get_deltas(&[(key_start, key_end)]);
            for delta in deltas {
                let  v = match delta {
                    Ok(r) => r.1.clone(),
                    Err(_) => Vec::new(),
                };
                deltas_vec.push(v);
            }
            let res = deltas_vec.into_iter().flatten().collect::<Vec<u8>>();
            ptr::copy_nonoverlapping(res.as_ptr(), res_ptr, res.len());
        }
    }
    0
}