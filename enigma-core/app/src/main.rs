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
#[macro_use]
extern crate log;
#[macro_use]
extern crate log_derive;
extern crate structopt;
extern crate simplelog;

mod common_u;
mod db;
mod esgx;
mod evm_u;
mod km_u;
mod networking;
mod wasm_u;
mod cli;
mod logging;

pub use crate::esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_home, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_save_to_memory, ocall_update_state};

use crate::networking::{constants, ipc_listener, IpcListener};
use crate::db::DB;
use crate::cli::Opt;
use structopt::StructOpt;
use futures::Future;
use simplelog::CombinedLogger;

fn main() {
    let opt: Opt = Opt::from_args();
    let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap());
    let loggers = logging::get_logger(opt.debug_stdout, datadir, opt.verbose).expect("Failed Creating the loggers");
    CombinedLogger::init(loggers).expect("Failed initializing the logger");
    debug!("CLI params: {:?}", opt);

    let enclave = esgx::general::init_enclave_wrapper().expect("[-] Init Enclave Failed");
    let eid = enclave.geteid();
    info!("[+] Init Enclave Successful {}!", eid);
    let enigma_dir = esgx::general::storage_dir();

    let mut db = DB::new(enigma_dir, true).expect("Failed initializing the DB");
    let server = IpcListener::new(&format!("tcp://*:{}", opt.port));

    server
        .run(move |multi| ipc_listener::handle_message(&mut db, multi, &opt.spid, eid))
        .wait()
        .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::esgx::general::init_enclave_wrapper;
    use sgx_types::*;
    use crate::db::tests::create_test_db;
    use enigma_types::RawPointer;
    use simplelog::TermLogger;
    use log::LevelFilter;

    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t, db_ptr: *const RawPointer) -> sgx_status_t;
    }


    pub fn log_to_stdout(level: LevelFilter) {
        TermLogger::init(level, Default::default()).unwrap();
    }

    #[test]
    pub fn test_enclave_internal() {
        let (mut db, _dir) = create_test_db();
        let enclave = init_enclave_wrapper().unwrap();
        let db_ptr = unsafe { RawPointer::new_mut(&mut db) };
        let ret = unsafe { ecall_run_tests(enclave.geteid(), &db_ptr as *const RawPointer) };

        assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
    }
}
