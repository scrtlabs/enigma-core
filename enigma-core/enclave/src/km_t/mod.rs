pub mod db;

use sgx_trts::trts::rsgx_read_rand;
use std::sync::SgxMutex;
use std::collections::HashMap;
use std::vec::Vec;
use std::slice;
use std::mem;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use crate::SIGNINING_KEY;
use enigma_types::EnclaveReturn;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::km_primitives::*;

lazy_static! { pub static ref DH_KEYS: SgxMutex< HashMap<ContractAddress, KeyPair >> = SgxMutex::new(HashMap::new()); }
lazy_static! { pub static ref State_Keys: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

#[no_mangle]
pub unsafe extern "C" fn ecall_ptt_req(address: *const ContractAddress, len: usize, sig: &mut [u8; 65]) {
    let address_list = slice::from_raw_parts(address, len/mem::size_of::<ContractAddress>());

//    let mut address_list: Vec<u8> = addresses[..].iter().flat_map(|arr| &arr[..]).cloned().collect();
//    req.extend_from_slice(address_list);

    println!("{:?}", address_list);
}

unsafe extern "C" fn ecall_ptt_req_internal (addresses: &[ContractAddress], sig: &mut [u8; 65]) -> Result<(), EnclaveError>{
    let mut req = b"Requesting keys for these contracts:".to_vec();
    let mut id = [0u8; 12];
    rsgx_read_rand(&mut id)?;

    Ok(())
}
