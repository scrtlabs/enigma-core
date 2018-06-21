use std::path;
use sgx_types::sgx_status_t;
use std::str;

const PATH_MAX: usize = 4096; // linux/limits.h - this depends on the FS.

extern { fn ocall_get_home(output: *mut u8, result_len: &mut usize) -> sgx_status_t; }

// TODO: Add Result.
pub fn get_home_path() -> path::PathBuf{
    // Get Home path via Ocall
    let mut home_slice: [u8; PATH_MAX] = [0; PATH_MAX];
    let mut result_len: usize = 0;
    unsafe { ocall_get_home(home_slice.as_mut_ptr(), &mut result_len); }
    let home_str = str::from_utf8(&home_slice[..result_len]).unwrap();
    println!("Back from Ocall: {}", &home_str);

    path::PathBuf::from(home_str)
}