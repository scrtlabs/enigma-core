
#![crate_name = "helloworldsampleenclave"]
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

extern crate sputnikvm;
extern crate hexutil;
extern crate bigint;
extern crate sputnikvm_network_classic;
extern crate ring;
extern crate secp256k1;
extern crate tiny_keccak;

mod common;
mod cryptography_t;
mod storage_t;
mod quote_t;
mod evm_t;

use sgx_trts::*;
use sgx_types::*;
use sgx_tse::*;

use std::ptr;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::str::from_utf8;
use std::string::ToString;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::path;

use hexutil::read_hex;
use evm_t::call_sputnikvm;
use cryptography_t::assymetric;
use common::utils_t::{ToHex, FromHex};
use storage_t::SecretKeyStorage;


/* this function is called every time the enclave is loaded */



#[no_mangle]
pub extern "C" fn registration_quote( target_info: &sgx_target_info_t , real_report: &mut sgx_report_t,
                                       home_ptr: *const u8, home_len: usize) -> sgx_status_t {

    // TODO: Check if the file already exists, if so load keys.
    // TODO: Or maybe the untrusted should verify it because there's no need to regenerate a key?
    lazy_static! { static ref SIGNINING_KEY: assymetric::KeyPair = assymetric::KeyPair::new(); };
    println!("{:?}", SIGNINING_KEY.get_pubkey()[..].to_hex());
    let data = storage_t::SecretKeyStorage {version: 0x1, data: SIGNINING_KEY.get_privkey()};
    let mut output: [u8; storage_t::SEAL_LOG_SIZE] = [0; storage_t::SEAL_LOG_SIZE];
    data.seal_key(&mut output);

    let _home_path = unsafe { slice::from_raw_parts(home_ptr, home_len) };
    let home_path = from_utf8(_home_path).unwrap();

    let mut seal_file = path::PathBuf::from(home_path);
    seal_file.push("keypair.sealed");
    let file = seal_file.to_str().unwrap();
    println!("Home: {:?}", file);
    storage_t::save_sealed_key(file, &output);

    quote_t::create_report_with_data(&target_info ,real_report,&SIGNINING_KEY.get_pubkey())
}


//#[allow(unused_variables, unused_mut)]
//#[no_mangle]
//pub extern "C" fn ecall_test_sealing_storage_key() -> sgx_status_t{
//    storage_t::test_full_sealing_storage();
//    sgx_status_t::SGX_SUCCESS
//}

#[no_mangle]
pub extern "C" fn ecall_evm(code: *const u8, code_len: usize, data: *const u8, data_len: usize, output: *mut u8, vm_status: &mut u8, result_len: &mut usize) -> sgx_status_t {
    let code_slice = unsafe { slice::from_raw_parts(code, code_len) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len) };

    let code = read_hex(from_utf8(code_slice).unwrap()).unwrap();
    let data = read_hex(from_utf8(data_slice).unwrap()).unwrap();

    let mut res = call_sputnikvm(code, data);
    let mut s: &mut [u8] = &mut res.1[..];
    *result_len = s.len();

    *vm_status = res.0;
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), output, s.len());
    }
    sgx_status_t::SGX_SUCCESS
}

pub mod tests {
//    #[macro_use]
    extern crate sgx_tunittest;
//    #[macro_use]
    extern crate sgx_tstd as std;
    use sgx_tunittest::*;
    use std::vec::Vec;
    use std::string::String;
    use cryptography_t::assymetric::tests::*;
    use storage_t::tests::*;

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
        test_full_sealing_storage,
        test_signing,
        test_ecdh
    );

    }
}
