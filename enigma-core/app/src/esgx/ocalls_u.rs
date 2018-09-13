use std::ptr;
use std::slice;
use std::ffi::CStr;
use std::os::raw::c_char;
use esgx::general;


#[no_mangle]
pub extern "C" fn ocall_get_home(output: *mut u8, result_len: &mut usize) {
    let path = general::storage_dir();
    let path_str = path.to_str().unwrap();
    unsafe { ptr::copy_nonoverlapping(path_str.as_ptr(), output, path_str.len()); }
    *result_len = path_str.len();
}

#[no_mangle]
pub extern "C" fn ocall_update_state(id: *const c_char, enc_state: *const u8, state_len: usize) -> i8 {
    let id_str = unsafe { CStr::from_ptr(id) }.to_str().unwrap();
    println!("*********** {}", id_str);
    let encrypted_state = unsafe { slice::from_raw_parts(enc_state, state_len) };
    println!("************** {:?}", encrypted_state);

    return 0;
}

#[no_mangle]
pub extern "C" fn ocall_new_delta(id: u64, enc_delta: *const u8, delta_len: usize) -> i8 {
    let encrypted_delta = unsafe { slice::from_raw_parts(enc_delta, delta_len) };
    println!("************** {:?}", encrypted_delta);


    return 0;

}