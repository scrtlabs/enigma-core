extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
extern crate reqwest;
extern crate dirs;

// networking apt install libzmq3-dev
extern crate zmq; 
extern crate serde_json;
// errors
#[macro_use]
extern crate failure;
extern crate rustc_hex as hex;

//enigma utils 
extern crate enigma_tools_u;

#[macro_use]
extern crate serde_derive;
extern crate serde;

//use sgx_types::*;
use std::thread;
// enigma modules 
mod esgx;
mod evm_u;
mod networking;
mod common_u;

pub use esgx::general::ocall_get_home;
use networking::{surface_server, constants};

#[allow(unused_variables, unused_mut)]
fn main() {
    /* this is an example of initiating an enclave */

    let enclave = match esgx::general::init_enclave_wrapper() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
    let eid = enclave.geteid();
    let child = thread::spawn(move || {
        let mut server = surface_server::Server::new(constants::CONNECTION_STR, eid);
        server.run();
    });
    child.join().unwrap();
   
    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use esgx::general::init_enclave_wrapper;
    use sgx_types::*;
    extern { fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t; }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave_wrapper() {
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
