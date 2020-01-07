#![warn(clippy::all)]
#![warn(unused_extern_crates)]

pub extern crate rocksdb;
pub extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate lazy_static;
pub extern crate futures;
extern crate rmp_serde;
pub extern crate serde_json;
extern crate tokio_zmq;
extern crate zmq;
#[macro_use]
extern crate failure;
pub extern crate enigma_tools_u;
extern crate enigma_tools_m;
extern crate enigma_crypto;
extern crate enigma_types;
extern crate rustc_hex as hex;
extern crate lru_cache;
#[macro_use]
extern crate serde;
extern crate serde_repr;
#[macro_use]
pub extern crate log;
#[macro_use]
pub extern crate log_derive;
pub extern crate structopt;

pub mod common_u;
pub mod db;
pub mod esgx;
pub mod km_u;
pub mod networking;
pub mod wasm_u;
pub mod cli;
pub mod auto_ffi;

#[cfg(feature = "cross-test-utils")]
pub mod cross_test_utils {
    use super::*;

}

#[cfg(test)]
mod tests {
    extern crate tempfile;
    use crate::esgx::general::init_enclave_wrapper;
    use sgx_types::*;
    use crate::db::DB;
    use enigma_types::{RawPointer, ResultStatus};
    use enigma_tools_u::common_u::logging;
    use log::LevelFilter;
    use self::tempfile::TempDir;
    use crate::auto_ffi::ecall_run_tests;


    /// It's important to save TempDir too, because when it gets dropped the directory will be removed.
    fn create_test_db() -> (DB, TempDir) {
        let tempdir = tempfile::tempdir().unwrap();
        let db = DB::new(tempdir.path(), true).unwrap();
        (db, tempdir)
    }

    #[allow(dead_code)]
    pub fn log_to_stdout(level: Option<LevelFilter>) {
        let level = level.unwrap_or_else(|| LevelFilter::max());
        logging::init_logger(level, ".", "Tests".to_string()).unwrap();
    }

    #[test]
    pub fn test_enclave_internal() {
        let (mut db, _dir) = create_test_db();
        let enclave = init_enclave_wrapper().unwrap();
        let db_ptr = unsafe { RawPointer::new_mut(&mut db) };
        let mut result: ResultStatus = ResultStatus::Ok;
        let ret = unsafe { ecall_run_tests(enclave.geteid(), &db_ptr as *const RawPointer, &mut result) };

        assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
        assert_eq!(result,ResultStatus::Ok);
    }
}
