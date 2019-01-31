#![feature(tool_lints)]
#![warn(clippy::all)]
#![feature(try_from)]

extern crate base64;
extern crate dirs;
extern crate reqwest;
extern crate rocksdb;
extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate lazy_static;
extern crate futures;
extern crate rmp_serde;
#[cfg_attr(test, macro_use)]
extern crate serde_json;
extern crate tokio;
extern crate tokio_zmq;
extern crate zmq;
#[macro_use]
extern crate failure;
extern crate enigma_tools_u;
extern crate enigma_crypto;
extern crate enigma_types;
extern crate rustc_hex as hex;
#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate lru_cache;
extern crate serde;
extern crate tempdir;
#[macro_use]
extern crate log;
#[macro_use]
extern crate log_derive;
extern crate structopt;

mod common_u;
mod db;
mod esgx;
mod evm_u;
mod km_u;
mod networking;
mod wasm_u;
mod cli;

use futures::Future;

pub use crate::esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_home, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_save_to_memory, ocall_update_state};

use networking::{ipc_listener, IpcListener};
use crate::cli::Opt;
use structopt::StructOpt;

fn main() {
    let opt = Opt::from_args();
    info!("CLI params: {:?}", opt);
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
    let server = IpcListener::new(&format!("tcp://localhost:{}", opt.port));
    server.run(move |multi| ipc_listener::handle_message(multi, &opt.spid, enclave.geteid())).wait().unwrap();
}

#[cfg(test)]
mod tests {
    use crate::esgx::general::init_enclave_wrapper;
    use sgx_types::*;
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
