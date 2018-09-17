use sgx_types::sgx_status_t;
use std::os::raw::c_char;
use std::ffi::{CStr, CString};
use std::string::ToString;
use enigma_tools_t::common::errors_t::EnclaveError::{self, OcallErr};
use state::{EncryptedContractState, EncryptedPatch};


extern { fn ocall_new_delta(retval: *mut i8, enc_delta: *const u8, delta_len: usize) -> sgx_status_t; }
extern { fn ocall_update_state(retval: *mut i8, id: *const c_char, enc_delta: *const u8, delta_len: usize) -> sgx_status_t; }


pub fn save_state(enc: &EncryptedContractState<u8>) -> Result<(), EnclaveError> {
    let id = CString::new(enc.contract_id.clone()).unwrap();
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
}


pub fn save_delta(enc: &EncryptedPatch) -> Result<(), EnclaveError> {
    let mut res_int: i8 = -1;
    let res_status: sgx_status_t = unsafe {
        ocall_new_delta(&mut res_int as *mut i8,  enc.as_ptr(), enc.len())
    };
    match res_int {
        0 => (), // 0 is the OK result
        _ => return Err( OcallErr { command: "ocall_new_delta".to_string(), err: format!("return result is: {}", &res_int ) } )
    }
    match res_status {
        sgx_status_t::SGX_SUCCESS => return Ok( () ),
        _ => return Err ( OcallErr { command: "ocall_new_delta".to_string(), err: res_status.__description().to_string() } )
    }
//    Ok( () )
}

use state::{StatePatch, Encryption};
use enigma_tools_t::common::utils_t::Sha256;
use serde_json;

pub fn test_me() {
    let a = CString::new("Yay!").unwrap();
    let mut b = 1i8;
    let c = [0,1,2,3];
    unsafe { ocall_update_state(&mut b as *mut i8, a.as_ptr() as *const c_char, c.as_ptr(), c.len()) };
    println!("{:?}", b);

    let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
    let patch: StatePatch = serde_json::from_str(p).unwrap();
    let key = b"EnigmaMPC".sha256();
    let iv = [0,1,2,3,4,5,6,7,8,9,10,11];
    let enc = patch.encrypt_with_nonce(&key, Some(&iv)).unwrap();
    println!("**** Delta before: {:?}", &enc);
    save_delta(&enc).unwrap();
}
