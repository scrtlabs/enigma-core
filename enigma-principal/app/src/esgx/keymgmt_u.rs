//sgx
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
// general
use rlp;
use enigma_tools_u;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::attestation_service::constants;
use failure::Error;

extern { fn ecall_set_worker_params(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, log: RawLog, sig_out: &mut [u8; 65]) -> sgx_status_t; }

/// Returns a 32 bytes signed random seed.
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let (rand_seed, sig) = get_signed_random(enclave.geteid());
/// ```
pub fn get_(eid: sgx_enclave_id_t) -> ([u8; 32], [u8; 65]) {
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    unsafe { ecall_get_random_seed(eid, &mut retval, &mut rand_out, &mut sig_out); }
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (rand_out, sig_out)
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use esgx;
    use sgx_urts::SgxEnclave;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str::from_utf8;
}
