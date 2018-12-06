#![allow(dead_code)] // TODO: Remove later

use sgx_types::{sgx_status_t, sgx_enclave_id_t};
use enigma_types::EnclaveReturn;
use failure::Error;
use crate::common_u::errors::EnclaveFailError;
use std::mem;

pub type ContractAddress = [u8; 32];
extern "C" {
    fn ecall_ptt_req(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn, addresses: *const ContractAddress, len: usize,
                     signature: &mut [u8; 65], serialized_ptr: *mut u64) -> sgx_status_t;
    fn ecall_ptt_res(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn, msg_ptr: *const u8, msg_len: usize) -> sgx_status_t;
    fn ecall_build_state(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn, failed_ptr: *mut u64) -> sgx_status_t;
}

pub fn ptt_build_state(eid: sgx_enclave_id_t) -> Result<Vec<ContractAddress>, Error> {
    let mut ret = EnclaveReturn::Success;
    let mut failed_ptr = 0u64;
    let status = unsafe { ecall_build_state(eid, &mut ret as *mut EnclaveReturn, &mut failed_ptr as *mut u64) };
    if ret != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: ret, status}.into());
    }
    let box_ptr = failed_ptr as *mut Box<[u8]>;
    let part = unsafe { Box::from_raw(box_ptr) };
    let part: Vec<ContractAddress> = part.chunks(32).map(|s| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        arr
    }).collect();
    Ok(part)
}


pub fn ptt_res(eid: sgx_enclave_id_t, msg: &[u8]) -> Result<(), Error> {
    let mut ret = EnclaveReturn::Success;
    let status = unsafe { ecall_ptt_res(eid, &mut ret as *mut EnclaveReturn, msg.as_ptr(), msg.len()) };
    if ret != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: ret, status}.into());
    }
    Ok(())
}



pub fn ptt_req(eid: sgx_enclave_id_t, addresses: &[ContractAddress]) -> Result<(Vec<u8>, [u8; 65]), Error> {
    let mut sig = [0u8; 65];
    let mut ret = EnclaveReturn::Success;
    let mut serialized_ptr = 0u64;

    let status = unsafe { ecall_ptt_req(eid,
                           &mut ret as *mut EnclaveReturn,
                           addresses.as_ptr() as *const ContractAddress,
                           addresses.len() * mem::size_of::<ContractAddress>(),
                           &mut sig,
                           &mut serialized_ptr as *mut u64
    )};
    if ret != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: ret, status}.into());
    }
    let box_ptr = serialized_ptr as *mut Box<[u8]>;
    let part = unsafe { Box::from_raw(box_ptr) };
    Ok( (part.to_vec(), sig) )
}

#[cfg(test)]
pub mod tests {
    use crate::esgx;
    use super::{ContractAddress, ptt_req};
    #[test]
    fn test_ecall() {
        let enclave = esgx::general::init_enclave_wrapper().unwrap();
        let addresses: [ContractAddress; 3] = [[1u8 ;32], [2u8; 32], [3u8; 32]];
        let (msg, sig) = ptt_req(enclave.geteid(), &addresses).unwrap();
        assert_ne!(msg.len(), 0);
        assert_ne!(sig.to_vec(), vec![0u8; 64]);
    }
}
