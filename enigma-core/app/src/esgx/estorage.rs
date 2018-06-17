use std;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::*;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
use std::ptr;
// write and read from files 
use std::fs::File;
use std::io::prelude::*;
// enigma modules
use esgx;

pub const SEALING_KEY_SIZE : usize = 32;
pub const SEAL_LOG_SIZE: usize = 2048;

use std::slice;


//// test method => to be deleted
//extern {
//    pub fn ecall_test_sealing_storage_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t)->sgx_status_t;
//}


// #[cfg(test)]
// mod test {
//    use esgx::general::init_enclave;
////    use esgx::estorage::ecall_test_sealing_storage_key;
//    use sgx_types::*;
//     #[test]
//     fn test_produce_quote(){
//            // initiate the enclave
//            let enclave = match init_enclave() {
//                Ok(r) => {
//                    println!("[+] Init Enclave Successful {}!", r.geteid());
//                    r
//                },
//                Err(x) => {
//                    println!("[-] Init Enclave Failed {}!", x.as_str());
//                    assert_eq!(0,1);
//                    return;
//                },
//            };
//
//        let mut ret : sgx_status_t = sgx_status_t::SGX_SUCCESS;
//         ret = unsafe {
//            ecall_test_sealing_storage_key(enclave.geteid(),&mut ret)
//         };
//        assert_eq!(ret,sgx_status_t::SGX_SUCCESS);
//        enclave.destroy();
//     }
// }