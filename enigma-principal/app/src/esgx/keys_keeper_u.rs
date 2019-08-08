use std::{convert::TryInto, mem};

use failure::Error;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use web3::types::{H256, U256};

use boot_network::keys_provider_http::{StateKeyRequest, StateKeyResponse, StringWrapper};
use common_u::errors::EnclaveFailError;
use enigma_types::{ContractAddress, EnclaveReturn, traits::SliceCPtr};

extern "C" {
    fn ecall_get_enc_state_keys(
        eid: sgx_enclave_id_t, retval: &mut EnclaveReturn, msg: *const u8, msg_len: usize, addrs: *const u8, addrs_len: usize,
        sig: &[u8; 65], epoch_nonce: &[u8; 32], serialized_ptr: *mut u64, sig_out: &mut [u8; 65],
    ) -> sgx_status_t;
}

/// Returns the signed encrypted keys.
///
/// # Arguments
/// * `eid` - The Enclave Id
/// * `request` - The `StateKeyRequest` object containing the query parameters
/// * `epoch_nonce` - The nonce of the epoch against which to run the worker selection algorithm
/// * `epoch_addrs` - Optional, the secret contract address requested. If none, the query will use addresses in the `StateKeyRequest`.
///
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let msg = StringWrapper("84a46461746181a75265717565737493dc0020cca7cc937b64ccb8cccacca5cc8f03721bccb6ccbacccf5c78cccb235fccebcce0cce70b1bcc84cccdcc99541461cca0cc8edc002016367accacccb67a4a017ccc8dcca8ccabcc95682ccccb390863780f7114ccddcca0cca0cce0ccc55644ccc7ccc4dc0020ccb1cce9cc9324505bccd32dcca0cce1ccf85dcccf5e19cca0cc9dccb0481ecc8a15ccf62c41cceb320304cca8cce927a269649c1363ccb3301c101f33cce1cc9a0524a67072656669789e456e69676d61204d657373616765a67075626b6579dc0040cce5ccbe28cc9dcc9a2eccbd08ccc0457a5f16ccdfcc9fccdc256c5d5f6c3514cccdcc95ccb47c11ccc4cccd3e31ccf0cce4ccefccc83ccc80cce8121c3939ccbb2561cc80ccec48ccbecca8ccc569ccd2cca3ccda6bcce415ccfa20cc9bcc98ccda".to_string());
/// let sig = StringWrapper("43f19586b0a0ae626b9418fe8355888013be1c9b4263a4b3a27953de641991e936ed6c4076a2a383b3b001936bf0eb6e23c78fbec1ee36f19c6a9d24d75e9e081c".to_string());
/// let request = StateKeyRequest { data: msg, sig: sig };
/// let nonce = U256::from(0);
/// let response = get_enc_state_keys(enclave.geteid(), request, nonce, None).unwrap();
/// ```
#[logfn(DEBUG)]
pub fn get_enc_state_keys(eid: sgx_enclave_id_t, request: StateKeyRequest, epoch_nonce: U256, sc_addrs: &[ContractAddress]) -> Result<StateKeyResponse, Error> {
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    let mut sig_out: [u8; 65] = [0; 65];
    let mut response_ptr = 0u64;
    let epoch_nonce: [u8; 32] = H256::from(epoch_nonce).0;

    let msg_bytes: Vec<u8> = request.data.try_into()?;
    let status = unsafe {
        ecall_get_enc_state_keys(
            eid,
            &mut retval,
            msg_bytes.as_c_ptr() as *const u8,
            msg_bytes.len(),
            sc_addrs.as_c_ptr() as *const u8,
            mem::size_of_val(sc_addrs),
            &request.sig.try_into()?,
            &epoch_nonce,
            &mut response_ptr as *mut u64,
            &mut sig_out,
        )
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    let box_ptr = response_ptr as *mut Box<[u8]>;
    let response = unsafe { Box::from_raw(box_ptr) };
    Ok(StateKeyResponse { data: StringWrapper::from(&response[..]), sig: StringWrapper::from(&sig_out[..]) })
}

#[cfg(test)]
pub mod tests {
    use sgx_urts::SgxEnclave;

    use esgx::epoch_keeper_u::set_or_verify_worker_params;
    use esgx::epoch_keeper_u::tests::get_worker_params;
    use esgx::general::init_enclave_wrapper;

    use super::*;

    fn init_enclave() -> SgxEnclave {
        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                panic!("[-] Init Enclave Failed {}!", x.as_str());
            }
        };
        enclave
    }

    //TODO: Test error scenario with `get_state_keys`

    #[test]
    fn test_get_state_keys() {
        let enclave = init_enclave();

        // Since the seed is not predictable in advance, test with a single worker to predict the selected worker
        let workers: Vec<[u8; 20]> = vec![[161, 186, 144, 238, 40, 242, 102, 161, 178, 93, 177, 83, 107, 128, 189, 132, 112, 8, 163, 252]];
        let stakes: Vec<u64> = vec![10000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        let epoch_state = set_or_verify_worker_params(enclave.geteid(), &worker_params, None).unwrap();

        // From the km_primitives uint tests
        let msg = StringWrapper("83a464617461a752657175657374a269649cccd763674174cc9b3f300dccd2ccb0cc8ba67075626b6579dc0040ccc90b2205ccf9cc9358661320ccffccb763ccb57614ccf8ccaa1fccb86d6a087869ccd81acce5ccf16fcc9206cc98344136cca4ccefccb105ccbbccca1c5057ccba25067eccc101cc82ccee21445cccf91e79ccb176447239".to_string());
        let sig = StringWrapper("2535cfe1bcea215dc552acbca1a213354e055709f8e071c593bb9a8c1551b7791d6fd611ded1912065b3b518f6a75a1c78643b0a2e06397707b21768be637cb41b".to_string());
        println!("The mock message: {:?}", msg);
        println!("The mock sig: {:?}", sig);

        let request = StateKeyRequest { data: msg, sig, block_number: None, addresses: None };
        let response = get_enc_state_keys(enclave.geteid(), request, epoch_state.nonce, &[]).unwrap();
        println!("Got response: {:?}", response);
        enclave.destroy();
    }
}
