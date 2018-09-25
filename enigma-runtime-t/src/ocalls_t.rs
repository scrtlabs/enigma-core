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

use state::Encryption;

pub fn test_me() {
    let enc_json = vec![215, 18, 107, 35, 28, 119, 236, 243, 75, 146, 131, 19, 155, 72, 164, 66, 80, 170, 84, 3, 35, 201, 202, 190, 74, 191, 203, 12, 19, 212, 170, 28, 211, 254, 8, 37, 129, 81, 171, 255, 108, 133, 117, 41, 189, 223, 169, 148, 180, 186, 123, 179, 38, 105, 24, 51, 170, 30, 119, 41, 216, 132, 156, 197, 183, 105, 14, 131, 142, 77, 205, 8, 17, 139, 152, 196, 117, 216, 241, 102, 227, 171, 158, 39, 228, 4, 232, 98, 253, 149, 139, 31, 177, 182, 199, 130, 233, 217, 38, 156, 203, 196, 157, 68, 171, 26, 225, 129, 58, 143, 42, 127, 97, 158, 93, 55, 214, 123, 232, 240, 250, 44, 168, 203, 156, 207, 172, 211, 169, 52, 241, 219, 186, 94, 201, 111, 185, 180, 219, 222, 123, 201, 167, 154, 173, 54, 51, 242, 121, 136, 203, 254, 135, 68, 127, 14, 248, 187, 99, 223, 19, 184, 108, 182, 230, 191, 89, 255, 103, 127, 183, 89, 166, 37, 93, 56, 147, 68, 184, 19, 20, 150, 241, 5, 45, 120, 254, 238, 164, 26, 154, 232, 54, 213, 1, 215, 248, 58, 172, 41, 195, 147, 68, 83, 34, 208, 23, 127, 95, 240, 87, 53, 202, 60, 224, 60, 209, 225, 33, 65, 193, 204, 185, 207, 146, 221, 251, 161, 31, 144, 237, 152, 209, 130, 146, 177, 37, 54, 107, 137, 111, 191, 134, 92, 0, 5, 46, 252, 136, 105, 37, 49, 143, 144, 45, 104, 79, 157, 87, 177, 199, 172, 67, 245, 44, 163, 102, 103, 240, 41, 159, 215, 149, 182, 103, 92, 144, 213, 112, 5, 248, 129, 128, 0, 55, 185, 137, 255, 87, 138, 231, 128, 222, 235, 253, 136, 166, 187, 21, 73, 238, 116, 89, 96, 3, 140, 193, 168, 142, 8, 247, 167, 246, 89, 199, 214, 199, 61, 92, 44, 203, 209, 211, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let id = "Enigma".to_string();
    let enc = EncryptedContractState { contract_id: id.clone(), json: enc_json };
    save_state(&enc).unwrap();

    let enc_patch: EncryptedPatch = vec![197, 39, 187, 56, 29, 96, 229, 230, 172, 82, 74, 89, 152, 72, 183, 136, 80, 182, 222, 4, 47, 197, 200, 233, 105, 90, 207, 14, 20, 220, 170, 226, 21, 241, 24, 231, 69, 27, 177, 234, 110, 132, 253, 115, 87, 205, 167, 142, 163, 170, 37, 239, 240, 98, 20, 49, 185, 223, 162, 115, 194, 220, 75, 218, 160, 17, 83, 134, 247, 239, 213, 207, 59, 32, 76, 204, 206, 134, 80, 234, 88, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    save_delta(&enc_patch).unwrap();
}
