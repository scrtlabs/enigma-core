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

use cli::options::Opt;
use enigma_tools_u::common_u::logging::{self, CombinedLogger};
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
    debug!("CLI params: {:?}", opt);

    let datadir = dirs::home_dir().unwrap().join(".enigma");
    let loggers = logging::get_logger(opt.debug_stdout, datadir.clone(), opt.verbose).expect("Failed Creating the loggers");
    CombinedLogger::init(loggers).expect("Failed initializing the logger");

    let enclave = esgx::general::init_enclave_wrapper().expect("[-] Init Enclave Failed");
    let eid = enclave.geteid();
    cli::app::start(eid).unwrap();
    info!("[+] Init Enclave Successful {}!", eid);

    // drop enclave when done
    enclave.destroy();
}

#[cfg(test)]
mod tests {
    use enigma_tools_u::common_u::logging::TermLogger;
    use esgx::general::init_enclave_wrapper;
    use log::LevelFilter;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};

    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
    }

    pub fn log_to_stdout(level: Option<LevelFilter>) {
        let level = level.unwrap_or_else(|| LevelFilter::max());
        TermLogger::init(level, Default::default()).unwrap();
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
