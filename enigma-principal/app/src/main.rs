#![feature(integer_atomics)]
#![feature(arbitrary_self_types)]
#[macro_use]
extern crate structopt;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate colour;
extern crate base64;
extern crate dirs;
extern crate enigma_tools_u;
extern crate enigma_types;
extern crate rustc_hex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tiny_keccak;
extern crate tokio_core;
extern crate url;
extern crate web3;
extern crate jsonrpc_minihttp_server;
extern crate ethabi;

//etcommon
extern crate rlp;
extern crate bigint;

// enigma modules
mod boot_network;
mod cli;
mod common_u;
mod esgx;

pub use esgx::general::ocall_get_home;

#[allow(unused_variables, unused_mut)]
fn main() {
    // init enclave
    let enclave = match esgx::general::init_enclave_wrapper() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    // run THE app
    let eid = enclave.geteid();
    cli::app::start(eid).unwrap();

    // drop enclave when done
    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use esgx::general::init_enclave_wrapper;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
    }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0, 1);
                return;
            }
        };
        let ret = unsafe { ecall_run_tests(enclave.geteid()) };
        assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}
