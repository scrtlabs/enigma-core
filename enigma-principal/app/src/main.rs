#[macro_use]
extern crate structopt;
#[macro_use]
extern crate failure;
extern crate url;
extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
extern crate rlp;
extern crate enigma_tools_u;
extern crate tiny_keccak;
extern crate serde_json;
extern crate serde;
extern crate serde_derive;
extern crate web3;
extern crate rustc_hex;
extern crate tokio_core;
// enigma modules
mod esgx;
mod common_u;
mod boot_network;
mod cli;
// general modules
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
pub use esgx::general::ocall_get_home;

#[allow(unused_variables, unused_mut)]
fn main() {

    /// init enclave 
    let enclave = match esgx::general::init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
    
    /// run THE app 
    /// 
    let eid = enclave.geteid();
    cli::app::start(eid);
    
    /// drop enclave when done 
    enclave.destroy();
}


#[cfg(test)]
mod tests {
    use esgx::general::init_enclave;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    extern { fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t; }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        let ret = unsafe { ecall_run_tests(enclave.geteid()) };
        assert_eq!(ret,sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}
