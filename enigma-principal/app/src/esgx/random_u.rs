//sgx
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern { fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t; }

/// Returns a 32 bytes signed random seed.
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let (rand_seed, sig) = get_signed_random(enclave.geteid());
/// ```
pub fn get_signed_random(eid: sgx_enclave_id_t) -> ([u8; 32], [u8; 65]) {
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    unsafe { ecall_get_random_seed(eid, &mut retval, &mut rand_out, &mut sig_out); }
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (rand_out, sig_out)
}

