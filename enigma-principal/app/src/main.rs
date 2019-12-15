#![feature(integer_atomics)]
#![feature(arbitrary_self_types)]

#[macro_use]
extern crate colour;
extern crate dirs;
extern crate enigma_crypto;
extern crate enigma_tools_m;
extern crate enigma_tools_u;
extern crate enigma_types;
extern crate ethabi;
#[macro_use]
extern crate failure;
extern crate jsonrpc_http_server;

#[macro_use]
extern crate log;
#[macro_use]
extern crate log_derive;

extern crate rlp;
extern crate rustc_hex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_types;
extern crate sgx_urts;
extern crate structopt;
extern crate url;
extern crate web3;
extern crate rmp_serde;
extern crate envy;
extern crate itertools;

extern crate secp256k1;


use std::str::FromStr;

use cli::options::Opt;
use enigma_tools_u::common_u::logging;
use enigma_tools_u::common_u::os;

pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
use structopt::StructOpt;

// enigma modules
mod boot_network;
mod cli;
mod common_u;
mod epoch_u;
mod esgx;

fn main() {
    let opt: Opt = Opt::from_args();

    let log_level = log::LevelFilter::from_str(&opt.log_level).unwrap();
    let datadir = dirs::home_dir().unwrap().join(".enigma");
    // let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap().join(".enigma"));
    let hostname = os::hostname();
    let _handler = logging::init_logger(log_level, &datadir, hostname);

    debug!("CLI params: {:?}", opt);

    let enclave = esgx::general::init_enclave_wrapper().expect("[-] Init Enclave Failed");
    let eid = enclave.geteid();
    cli::app::start(eid).unwrap();
    info!("[+] Init Enclave Successful {}!", eid);

    // drop enclave when done
    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use enigma_tools_u::common_u::logging;
    use esgx::general::init_enclave_wrapper;
    use log::LevelFilter;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    use std::path::Path;

    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
    }

    pub fn log_to_stdout(level: Option<LevelFilter>) {
        let level = level.unwrap_or_else(|| LevelFilter::max());
        logging::init_logger(level, ".", "Tests".to_string()).unwrap();
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
