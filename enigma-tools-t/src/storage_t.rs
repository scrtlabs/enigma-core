#[cfg(not(target_env = "sgx"))]
use sgx_types::{sgx_status_t, sgx_sealed_data_t,sgx_attributes_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use std::untrusted::fs::File;
use std::untrusted::fs::remove_file;
use std::io::{Read, Write};
use std::string::*;



pub const SEALING_KEY_SIZE : usize = 32;
pub const SEAL_LOG_SIZE: usize = 2048;

#[derive(Copy, Clone, Default, Debug)]
pub struct SecretKeyStorage {
    pub version :u32, 
    pub data: [u8; SEALING_KEY_SIZE],
}
unsafe impl ContiguousMemory for SecretKeyStorage {}

impl SecretKeyStorage {

    /// safe seal
    /// param: the_data : clear text to be sealed
    /// param: sealed_log_out : the output of the sealed data
    pub fn seal_key(&self, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) {
        let additional: [u8; 0] = [0_u8; 0];
        let attribute_mask = sgx_attributes_t { flags: 0xfffffffffffffff3, xfrm: 0 };
        let sealed_data = SgxSealedData::<SecretKeyStorage>::seal_data_ex(
            0x0001, //key policy
            attribute_mask,
            0, //misc mask
            &additional,
            &self)
            .unwrap();
        // to sealed_log ->
        //    let mut sealed_log_arr:[u8;2048] = [0;2048];
        let sealed_log = sealed_log_out.as_mut_ptr();
        let sealed_log_size: usize = 2048;
        to_sealed_log(&sealed_data, sealed_log, sealed_log_size as u32);
    }

    // TODO: Add Error Handling.
    /// unseal key
    /// param: sealed_log_in : the encrypted blob
    /// param: udata : the SecreyKeyStorage (clear text)
    pub fn unseal_key(sealed_log_in: &mut [u8]) -> Option<SecretKeyStorage> {
        let sealed_log_size: usize = SEAL_LOG_SIZE;
        let sealed_log = sealed_log_in.as_mut_ptr();
        let sealed_data = from_sealed_log::<SecretKeyStorage>(sealed_log, sealed_log_size as u32)?;
        let unsealed_result = sealed_data.unseal_data();
        match unsealed_result {
            Ok(unsealed_data) => {
                let mut udata = unsealed_data.get_decrypt_txt();
                return Some(*udata)
            }
            Err(err) => {
                // TODO: Handle this. It can causes panic in Simulation Mode until deleting the file.
                if err == sgx_status_t::SGX_ERROR_MAC_MISMATCH { return None }
                else { panic!(err) }
            }
        }
    }
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

// file system
pub fn save_sealed_key(path : &str , sealed_key : & [u8]){
     let opt = File::create(path);
    if opt.is_ok(){
        println!("Created file => {} ",path);
        let mut file = opt.unwrap();
        let result = file.write_all(&sealed_key);
        if result.is_ok(){
            println!("success writting to file! " );
        }else{
            println!("error writting to file! " );
        }
    }
}


pub fn load_sealed_key(path : &str , sealed_key : &mut [u8]){
     let opt = File::open(path);
    if opt.is_ok(){
        println!("Created file => {} ",path);
        let mut file = opt.unwrap();
        let result = file.read(sealed_key);
        if result.is_ok(){
            println!("success writting to file! " );
        }else{
            println!("error writting to file! " );
        }
    }
}


pub mod tests {
    use storage_t::*;
    //use std::untrusted::fs::*;

    /* Test functions */
    pub fn test_full_sealing_storage() {
        // generate mock data
        let mut data = SecretKeyStorage::default();
        data.version = 0x1234;
        for i in 0..32{
            data.data[i] = 'i' as u8;
        }
        // seal data
        let mut sealed_log_in:[u8;SEAL_LOG_SIZE] = [0;SEAL_LOG_SIZE];
        data.seal_key(&mut sealed_log_in);
        // save sealed_log to file
        let p = String::from("seal_test.sealed");
        save_sealed_key( &p, &sealed_log_in);
        // load sealed_log from file
        let mut sealed_log_out:[u8;SEAL_LOG_SIZE] = [0;SEAL_LOG_SIZE];
        load_sealed_key( &p, &mut sealed_log_out);
        // unseal data
        let unsealed_data = SecretKeyStorage::unseal_key(&mut sealed_log_out).unwrap();
        // compare data
        assert_eq!(data.data,unsealed_data.data);
        // delete the file
        let f = remove_file(&p);
        assert!(f.is_ok());
    }
}

