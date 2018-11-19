use enigma_tools_u::common_u::Keccak256;
use sgx_types::{sgx_status_t, sgx_enclave_id_t};
use esgx;
use std::mem;

type ContractAddress = [u8; 32];
extern {
    fn ecall_ptt_req(eid: sgx_enclave_id_t, address: *const ContractAddress, len: usize, signature: &mut [u8; 65]) -> sgx_status_t;
}


#[test]
fn test_ecall() {
    let enclave = match esgx::general::init_enclave_wrapper() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            panic!("[-] Init Enclave Failed {}!", x.as_str());
        }
    };

//    let addresses: [ContractAddress; 3] = [b"eng1".keccak256(), b"eng2".keccak256(), b"eng3".keccak256()];
    let addresses: [ContractAddress; 3] = [[1u8 ;32], [2u8; 32], [3u8; 32]];
//    let address_list: Vec<u8> = addresses[..].iter().flatten().cloned().collect();
    let mut sig = [0u8; 65];
    unsafe { ecall_ptt_req(enclave.geteid(),
                           addresses.as_ptr() as *const ContractAddress,
                           addresses.len() * mem::size_of::<ContractAddress>(),
                           &mut sig
    )};


}