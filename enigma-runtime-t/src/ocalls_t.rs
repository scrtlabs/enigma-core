use crate::data::{EncryptedContractState, EncryptedPatch};
use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, EnclaveSystemError::*};
use enigma_types::{ContractAddress, EnclaveReturn, traits::SliceCPtr, RawPointer};
use sgx_types::sgx_status_t;
use std::string::ToString;
use std::vec::Vec;

extern "C" {
    fn ocall_get_deltas_sizes(retval: *mut EnclaveReturn, db_ptr: *const RawPointer, addr: &ContractAddress,
                              start: *const u32, end: *const u32,
                              res_ptr: *mut usize, res_len: usize) -> sgx_status_t;
    fn ocall_get_deltas(retval: *mut EnclaveReturn, db_ptr: *const RawPointer, addr: &ContractAddress,
                        start: *const u32, end: *const u32,
                        res_ptr: *mut u8, res_len: usize) -> sgx_status_t;
    fn ocall_new_delta(retval: *mut EnclaveReturn, db_ptr: *const RawPointer,
                       enc_delta: *const u8, delta_len: usize,
                       contract_address: &ContractAddress, delta_index_: *const u32) -> sgx_status_t;
    fn ocall_remove_delta(retval: *mut EnclaveReturn, db_ptr: *const RawPointer,
                       contract_address: &ContractAddress, delta_index_: *const u32) -> sgx_status_t;

    fn ocall_get_state_size(retval: *mut EnclaveReturn, db_ptr: *const RawPointer, addr: &ContractAddress, state_len: *mut usize) -> sgx_status_t;
    fn ocall_get_state(retval: *mut EnclaveReturn, db_ptr: *const RawPointer, addr: &ContractAddress, state_ptr: *mut u8, state_len: usize) -> sgx_status_t;
    fn ocall_update_state(retval: *mut EnclaveReturn, db_ptr: *const RawPointer, id: &ContractAddress, enc_delta: *const u8, delta_len: usize) -> sgx_status_t;
}

pub unsafe fn save_state(db_ptr: *const RawPointer, enc: &EncryptedContractState<u8>) -> Result<(), EnclaveError> {
    let mut retval = EnclaveReturn::default();
    let res_status: sgx_status_t = ocall_update_state(&mut retval, db_ptr, &enc.contract_address, enc.json.as_c_ptr(), enc.json.len());
    match retval {
        EnclaveReturn::Success => (), // 0 is the OK result
        _ => return Err(SystemError(OcallError { command: "ocall_update_state".to_string(), err: format!("return result is: {}", &retval) })),
    }
    match res_status {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(SystemError(OcallError { command: "ocall_update_state".to_string(), err: res_status.__description().to_string() })),
    }
}

pub fn save_delta(db_ptr: *const RawPointer, enc: &EncryptedPatch) -> Result<(), EnclaveError> {
    let mut res = EnclaveReturn::default();
    let res_status =
        unsafe { ocall_new_delta(&mut res, db_ptr, enc.data.as_c_ptr(), enc.data.len(), &enc.contract_address, &enc.index as *const u32) };

    match res {
        EnclaveReturn::Success => (), // 0 is the OK result
        EnclaveReturn::OcallDBError => {
            return Err(SystemError(OcallError { command: "ocall_new_delta".to_string(), err: "key already exist".to_string() }))
        }
        _ => return Err(SystemError(OcallError { command: "ocall_new_delta".to_string(), err: format!("return result is: {}", &res) })),
    }

    match res_status {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(SystemError(OcallError { command: "ocall_new_delta".to_string(), err: res_status.__description().to_string() })),
    }
}

pub fn remove_delta(db_ptr: *const RawPointer, enc: &EncryptedPatch) -> Result<(), EnclaveError> {
    let mut res = EnclaveReturn::default();
    let res_status =
        unsafe { ocall_remove_delta(&mut res, db_ptr, &enc.contract_address, &enc.index as *const u32) };

    match res {
        EnclaveReturn::Success => (), // 0 is the OK result
        EnclaveReturn::OcallDBError => {
            return Err(SystemError(OcallError { command: "ocall_remove_delta".to_string(), err: "unable to remove the delta".to_string() }))
        }
        _ => return Err(SystemError(OcallError { command: "ocall_remove_delta".to_string(), err: format!("return result is: {}", &res) })),
    }

    match res_status {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(SystemError(OcallError { command: "ocall_remove_delta".to_string(), err: res_status.__description().to_string() })),
    }
}

pub fn get_state(db_ptr: *const RawPointer, contract_address: ContractAddress) -> Result<EncryptedContractState<u8>, EnclaveError> {
    let mut retval = EnclaveReturn::default();
    let mut state_len = 0usize;
    let status = unsafe { ocall_get_state_size(&mut retval, db_ptr, &contract_address, &mut state_len) };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(SystemError(OcallError {
            command: "get_state_size".to_string(),
            err: format!("Error with SGX, retval: {}, status: {:?}", retval, status),
        }));
    }
    let mut state = vec![0u8; state_len];
    let status = unsafe { ocall_get_state(&mut retval, db_ptr, &contract_address, state.as_mut_ptr(), state_len) };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(SystemError(OcallError {
            command: "get_state".to_string(),
            err: format!("Error with SGX, retval: {}, status: {:?}", retval, status),
        }));
    }

    Ok(EncryptedContractState { contract_address, json: state })
}

pub fn get_deltas(db_ptr: *const RawPointer, contract_address: ContractAddress, start: u32, end: u32) -> Result<Vec<EncryptedPatch>, EnclaveError> {
    let len = (end - start) as usize;
    let mut deltas_buff = vec![0usize; len];
    let mut retval = EnclaveReturn::default();
    let status =
        unsafe { ocall_get_deltas_sizes(&mut retval, db_ptr, &contract_address, &start as *const u32, &end as *const u32, deltas_buff.as_mut_ptr(), len) };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(SystemError(OcallError {
            command: "get_deltas".to_string(),
            err: format!("Error with SGX, retval: {}, status: {:?}", retval, status),
        }));
    }
    let mut deltas: Vec<u8> = deltas_buff.iter().map(|len| vec![0u8; (*len) as usize]).flatten().collect();
    let status =
        unsafe { ocall_get_deltas(&mut retval, db_ptr, &contract_address, &start as *const u32, &end as *const u32, deltas.as_mut_ptr(), deltas.len()) };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(SystemError(OcallError {
            command: "get_deltas".to_string(),
            err: format!("Error with SGX, retval: {}, status: {:?}", retval, status),
        }));
    }

    let mut result = Vec::new();
    let mut iteration = &deltas[..];
    for (i, size) in deltas_buff.into_iter().enumerate() {
        let tmp_slices = iteration.split_at(size as usize);
        if tmp_slices.0.is_empty() {
            continue;
        }
        let delta = EncryptedPatch { data: tmp_slices.0.to_vec(), contract_address, index: start + i as u32 };
        result.push(delta);
        iteration = tmp_slices.1;
    }
    Ok(result)
}


#[cfg(debug_assertions)]
pub mod tests {
    use super::{get_deltas, get_state, save_delta, save_state, EncryptedContractState, EncryptedPatch};
    use crate::data::ContractState;
    use enigma_types::{ContractAddress, RawPointer};
    use enigma_crypto::hash::Sha256;
    use enigma_crypto::Encryption;
    use serde_json::Value;
    use std::vec::Vec;
    use ocalls_t::remove_delta;

    pub unsafe fn test_me(db_ptr: *const RawPointer) {
        let enc_json = vec![215, 18, 107, 35, 28, 119, 236, 243, 75, 146, 131, 19, 155, 72, 164, 66, 80, 170, 84, 3, 35, 201, 202, 190, 74, 191, 203, 12, 19, 212, 170, 28, 211, 254, 8, 37, 129, 81, 171, 255, 108, 133, 117, 41, 189, 223, 169, 148, 180, 186, 123, 179, 38, 105, 24, 51, 170, 30, 119, 41, 216, 132, 156, 197, 183, 105, 14, 131, 142, 77, 205, 8, 17, 139, 152, 196, 117, 216, 241, 102, 227, 171, 158, 39, 228, 4, 232, 98, 253, 149, 139, 31, 177, 182, 199, 130, 233, 217, 38, 156, 203, 196, 157, 68, 171, 26, 225, 129, 58, 143, 42, 127, 97, 158, 93, 55, 214, 123, 232, 240, 250, 44, 168, 203, 156, 207, 172, 211, 169, 52, 241, 219, 186, 94, 201, 111, 185, 180, 219, 222, 123, 201, 167, 154, 173, 54, 51, 242, 121, 136, 203, 254, 135, 68, 127, 14, 248, 187, 99, 223, 19, 184, 108, 182, 230, 191, 89, 255, 103, 127, 183, 89, 166, 37, 93, 56, 147, 68, 184, 19, 20, 150, 241, 5, 45, 120, 254, 238, 164, 26, 154, 232, 54, 213, 1, 215, 248, 58, 172, 41, 195, 147, 68, 83, 34, 208, 23, 127, 95, 240, 87, 53, 202, 60, 224, 60, 209, 225, 33, 65, 193, 204, 185, 207, 146, 221, 251, 161, 31, 144, 237, 152, 209, 130, 146, 177, 37, 54, 107, 137, 111, 191, 134, 92, 0, 5, 46, 252, 136, 105, 37, 49, 143, 144, 45, 104, 79, 157, 87, 177, 199, 172, 67, 245, 44, 163, 102, 103, 240, 41, 159, 215, 149, 182, 103, 92, 144, 213, 112, 5, 248, 129, 128, 0, 55, 185, 137, 255, 87, 138, 231, 128, 222, 235, 253, 136, 166, 187, 21, 73, 238, 116, 89, 96, 3, 140, 193, 168, 142, 8, 247, 167, 246, 89, 199, 214, 199, 61, 92, 44, 203, 209, 211, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let contract_address = b"Enigma".sha256();
        let enc = EncryptedContractState { contract_address, json: enc_json };
        save_state(db_ptr, &enc).unwrap();

        let enc_patch = EncryptedPatch {
            data: vec![197, 39, 187, 56, 29, 96, 229, 230, 172, 82, 74, 89, 152, 72, 183, 136, 80, 182, 222, 4, 47, 197, 200, 233, 105, 90, 207, 14, 20, 220, 170, 226, 21, 241, 24, 231, 69, 27, 177, 234, 110, 132, 253, 115, 87, 205, 167, 142, 163, 170, 37, 239, 240, 98, 20, 49, 185, 223, 162, 115, 194, 220, 75, 218, 160, 17, 83, 134, 247, 239, 213, 207, 59, 32, 76, 204, 206, 134, 80, 234, 88, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            contract_address: [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162].into(),
            index: 57
        };
        save_delta(db_ptr, &enc_patch).unwrap();
    }

    pub unsafe fn test_get_deltas(db_ptr: *const RawPointer) {
        let contract_address = b"test_get_deltas".sha256();
        let (start, end) = (1, 7);
        let deltas = save_deltas(db_ptr, start, end, &contract_address);
        let res = get_deltas(db_ptr, contract_address, start, end).unwrap();
        assert_eq!(res, deltas);
    }

    pub unsafe fn test_get_deltas_more(db_ptr: *const RawPointer) {
        let contract_address = b"test_get_deltas_more".sha256();
        let (start, end) = (1, 15);
        let deltas = save_deltas(db_ptr, start, end, &contract_address);
        let res = get_deltas(db_ptr, contract_address, start, end + 3).unwrap();
        assert_eq!(res, deltas);
    }

    pub unsafe fn test_state(db_ptr: *const RawPointer) {
        let contract_address = b"test_state".sha256();
        let json = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/prize.json"));
        let v: Value = serde_json::from_str(json).unwrap();
        let state = ContractState { contract_address, json: v, .. Default::default() };
        let enc = state.encrypt(&b"Enigma".sha256()).unwrap();
        save_state(db_ptr, &enc).unwrap();
        let ret = get_state(db_ptr, contract_address).unwrap();
        assert_eq!(enc, ret);
    }

    pub fn test_remove_delta(db_ptr: *const RawPointer) {
        let contract_address = b"test_delta_removal".sha256();
        let (start, end) = (0, 1);
        let deltas = unsafe { save_deltas(db_ptr, start, end, &contract_address) };
        let res = remove_delta(db_ptr, deltas.last().unwrap());
        assert!(res.is_ok());
    }

    unsafe fn save_deltas(db_ptr: *const RawPointer, start: u32, end: u32, contract_address: &ContractAddress) -> Vec<EncryptedPatch> {
        let mut deltas = Vec::new();
        for i in start..end {
            let mut delta_data = b"data".sha256().to_vec();
            delta_data.push(i as u8);
            let delta = EncryptedPatch { data: delta_data, contract_address: *contract_address, index: i };
            deltas.push(delta.clone());
            save_delta(db_ptr, &delta).unwrap();
        }
        deltas
    }
}
