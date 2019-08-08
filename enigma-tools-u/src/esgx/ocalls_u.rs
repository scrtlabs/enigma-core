#![allow(unused_attributes)]

use std::{ptr, slice};
use enigma_types::traits::SliceCPtr;
use crate::esgx::general;

pub static ENCLAVE_DIR: &'static str = ".enigma";

#[no_mangle]
pub unsafe extern "C" fn ocall_get_home(output: *mut u8, result_len: &mut usize) {
    let path = general::storage_dir(ENCLAVE_DIR).unwrap(); // TODO: Handle the Error here. it wasn't handled before.
    let path_str = path.to_str().unwrap();
    ptr::copy_nonoverlapping(path_str.as_c_ptr(), output, path_str.len());
    *result_len = path_str.len();
}

#[no_mangle]
pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
    ptr as u64
}