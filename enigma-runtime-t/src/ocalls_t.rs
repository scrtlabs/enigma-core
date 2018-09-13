use sgx_types::sgx_status_t;
use std::os::raw::c_char;
use std::ffi::{CStr, CString};
use std::string::ToString;
use enigma_tools_t::common::errors_t::EnclaveError::{self, OcallErr};
use state::EncryptedContractState;

const PATH_MAX: usize = 4096; // linux/limits.h - this depends on the FS.

extern { fn ocall_new_delta(retval: *mut i8, id: u64, enc_delta: *const u8, delta_len: usize) -> sgx_status_t; }
extern { fn ocall_update_state(retval: *mut i8, id: *const c_char, enc_delta: *const u8, delta_len: usize) -> sgx_status_t; }

pub fn save_state(enc: EncryptedContractState<u8>) -> Result<(), EnclaveError> {
    let id = CString::new(enc.contract_id).unwrap();
    let mut res_int: i8 = -1;
    let res_status: sgx_status_t = unsafe {
        ocall_update_state(&mut res_int as *mut i8, id.as_ptr(), enc.json.as_ptr(), enc.json.len())
    };
    match res_int {
        0 => (), // 0 is the OK result
        _ => return Err( OcallErr { command: "ocall_update_state".to_string(), err: format!("return result is: {}", &res_int ) } )
    }
    match res_status {
        sgx_status_t::SGX_SUCCESS => return Ok( () ),
        _ => return Err ( OcallErr { command: "ocall_update_state".to_string(), err: res_status.__description().to_string() } )
    }
//    Ok( () )
}

pub fn test_me() {
    let a = "Yay!";
    let mut b = 1i8;
    let c = [0,1,2,3];
    unsafe { ocall_update_state(&mut b as *mut i8, a.as_ptr() as *const c_char, c.as_ptr(), c.len()) };
    println!("{:?}", b);
}