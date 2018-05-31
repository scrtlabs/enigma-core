//#![crate_name = "sealdatasampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};

static SEALING_KEY_SIZE : usize = 32;
#[derive(Copy, Clone, Default, Debug)]

pub struct SecretKeyStorage {
    version :u32, 
    data: [u8; 32],
}

unsafe impl ContiguousMemory for SecretKeyStorage {}

pub fn seal_key2(clear_key : &[u8;32]) -> Option<* mut sgx_sealed_data_t>{

    let mut data = SecretKeyStorage{version:0, data: *clear_key};
    let additional : [u8;0] = [0_u8; 0];
    let sealed_data = SgxSealedData::<SecretKeyStorage>::seal_data(&additional, &data).unwrap();
    // to sealed_log -> 
    let mut sealed_log_arr:[u8;2048] = [0;2048];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let sealed_log_size : u32 = 2048;
    to_sealed_log(&sealed_data, sealed_log, sealed_log_size)
}

// Some(SecretKeyStorage)
// None
pub fn unseal_key(sealed_log: * mut u8) -> Option<SecretKeyStorage> {
    let sealed_log_size : u32 = 2048;
    let sealed_data = from_sealed_log::<SecretKeyStorage>(sealed_log, sealed_log_size).unwrap();
    let unsealed_data = sealed_data.unseal_data().unwrap();
    let udata = unsealed_data.get_decrypt_txt();
    Some(*udata)
}

// delete 


pub fn seal_key(clear_key : &[u8;32]) -> * mut u8 {

    let mut data = SecretKeyStorage{version:0, data: *clear_key};
    let additional : [u8;0] = [0_u8; 0];
    let sealed_data = SgxSealedData::<SecretKeyStorage>::seal_data(&additional, &data).unwrap();
    // to sealed_log -> 
    let mut sealed_log_arr:[u8;2048] = [0;2048];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let sealed_log_size : u32 = 2048;
    to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    sealed_log
}


///
pub fn test_seal_unseal(){
    // create data 
    let mut data = SecretKeyStorage::default();
    data.version = 0x1234;
    for i in 0..32{
        data.data[i] = 'i' as u8;
    }
    println!("pre-sealing data = {:?}",data);
    let additional : [u8;0] = [0_u8; 0];
    let sealed_data = SgxSealedData::<SecretKeyStorage>::seal_data(&additional, &data).unwrap();
    // to sealed_log -> 
    let mut sealed_log_arr:[u8;2048] = [0;2048];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let sealed_log_size : u32 = 2048;
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    // done sealing. 
    // unsealing: 
    let sealed_data = from_sealed_log::<SecretKeyStorage>(sealed_log, sealed_log_size).unwrap();
    let unsealed_data = sealed_data.unseal_data().unwrap();
    let udata = unsealed_data.get_decrypt_txt();
    println!(" unsealed data = {:?}", udata);
}

fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}




