
#![crate_name = "enigma_principal_enclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate sgx_tunittest;
extern crate sgx_types;
extern crate sgx_tse;
extern crate sgx_trts;
// sealing
extern crate sgx_tseal;
extern crate sgx_rand;

#[macro_use]
extern crate lazy_static;

extern crate enigma_tools_t;

mod ocalls_t;

use sgx_types::{sgx_status_t, sgx_target_info_t, sgx_report_t};
use sgx_trts::trts::rsgx_read_rand;

use enigma_tools_t::cryptography_t;
use enigma_tools_t::cryptography_t::asymmetric;
use enigma_tools_t::common::utils_t::{ToHex, FromHex};
use enigma_tools_t::storage_t;
use enigma_tools_t::quote_t;


lazy_static! { static ref SIGNINING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper(); }


#[no_mangle]
pub extern "C" fn ecall_get_registration_quote( target_info: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
    println!("Generating Report with: {:?}", SIGNINING_KEY.get_pubkey()[..].to_hex());
    quote_t::create_report_with_data(&target_info ,real_report,&SIGNINING_KEY.get_pubkey())
}

fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

        // TODO: Decide what to do if failed to obtain keys.
    match cryptography_t::get_sealed_keys(&sealed_path) {
        Ok(key) => return key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err)
    };
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_pubkey(pubkey: &mut [u8; 64]) {
    pubkey.clone_from_slice(&SIGNINING_KEY.get_pubkey());
}


/// This is an ecall function that returns a signed seed and a signature.
/// Use this from outside of the enclave
/// # Examples
/// ```
/// extern { fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t; }
/// let enclave = esgx::general::init_enclave.unwrap();
/// let mut rand_out: [u8; 32] = [0; 32];
/// let mut sig_out: [u8; 65] = [0; 65];
/// let mut retval = sgx_status_t::default();
/// unsafe { ecall_get_random_seed(enclave.geteid(), &mut retval, &mut rand_out, &mut sig_out); }
/// ```
#[no_mangle]
pub extern "C" fn ecall_get_random_seed(rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t  {
    // TODO: Check if needs to check the random is within the curve.
    let status = rsgx_read_rand(&mut rand_out[..]);
    let sig = SIGNINING_KEY.sign(&rand_out[..]).unwrap();
    sig_out.copy_from_slice(sig.as_slice());
    println!("Random inside Enclave: {:?}", &rand_out[..]);
    println!("Signature inside Enclave: {:?}\n", &sig.as_slice());
    match status {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err
    }
}


pub mod tests {
    extern crate sgx_tunittest;
    extern crate sgx_tstd as std;
    extern crate enigma_tools_t;

    use sgx_tunittest::*;
    use std::vec::Vec;
    use std::string::String;
    use enigma_tools_t::cryptography_t::asymmetric::tests::*;
    use enigma_tools_t::storage_t::tests::*;

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
        test_full_sealing_storage,
        test_signing,
        test_ecdh
        );
    }
}
