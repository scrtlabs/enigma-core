use enigma_tools_t::common::errors_t::EnclaveError;
use sgx_types::sgx_status_t;
use std::path;
use std::str;

const PATH_MAX: usize = 4096; // linux/limits.h - this depends on the FS.



extern "C" {
    fn ocall_get_home(output: *mut u8, result_len: &mut usize) -> sgx_status_t;
    fn ocall_save_to_memory(ptr: *mut u64, data_ptr: *const u8, data_len: usize) -> sgx_status_t;
}

pub fn get_home_path() -> Result<path::PathBuf, EnclaveError> {
    // Get Home path via Ocall
    let mut home_slice: [u8; PATH_MAX] = [0; PATH_MAX];
    let mut result_len: usize = 0;
    unsafe { ocall_get_home(home_slice.as_mut_ptr(), &mut result_len); }
    let home_str = str::from_utf8(&home_slice[..result_len])?;
    println!("Back from Ocall: {}", &home_str);

    Ok(path::PathBuf::from(home_str))
}

pub fn save_to_untrusted_memory(data: &[u8]) -> Result<u64, EnclaveError> {
    let mut ptr = 0u64;

    //TODO: change this temporary solution for a problematic as_ptr implementation if empty vec
    let mut data = data.clone();
    if data.is_empty() {
        data = &[];
    }
    match unsafe { ocall_save_to_memory(&mut ptr as *mut u64, data.as_ptr(), data.len()) } {
        sgx_status_t::SGX_SUCCESS => Ok(ptr),
        e => Err(e.into()),
    }
}
