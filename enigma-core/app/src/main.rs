extern crate enigma_core_app;
#[macro_use]
extern crate log;
pub extern crate log_derive;

use cli::Opt;
pub use crate::esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_state, ocall_get_state_size, ocall_new_delta,
                                ocall_update_state};
use db::DB;
pub use enigma_core_app::*;
use enigma_tools_u::common_u::logging::{self, CombinedLogger};
pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
use futures::Future;
use networking::{ipc_listener, IpcListener};
use structopt::StructOpt;

fn main() {
    let opt: Opt = Opt::from_args();
    debug!("CLI params: {:?}", opt);

    let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap().join(".enigma"));
    let loggers = logging::get_logger(opt.debug_stdout, datadir.clone(), opt.verbose).expect("Failed Creating the loggers");
    CombinedLogger::init(loggers).expect("Failed initializing the logger");

    let enclave = esgx::general::init_enclave_wrapper().expect("[-] Init Enclave Failed");
    let eid = enclave.geteid();
    info!("[+] Init Enclave Successful {}!", eid);

    let mut db = DB::new(datadir, true).expect("Failed initializing the DB");
    let server = IpcListener::new(&format!("tcp://*:{}", opt.port));

    server.run(move |multi| ipc_listener::handle_message(&mut db, multi, &opt.spid, eid)).wait().unwrap();
}

#[cfg(test)]
mod tests {
    extern crate enigma_types;
    extern crate tempfile;
    use enigma_core_app::esgx::general::init_enclave_wrapper;
    use enigma_core_app::sgx_types::*;
    use enigma_core_app::db::DB;
    use self::enigma_types::RawPointer;
    use enigma_tools_u::common_u::logging::TermLogger;
    use enigma_core_app::log::LevelFilter;
    use self::tempfile::TempDir;

    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t, db_ptr: *const RawPointer) -> sgx_status_t;
    }

    /// It's important to save TempDir too, because when it gets dropped the directory will be removed.
    fn create_test_db() -> (DB, TempDir) {
        let tempdir = tempfile::tempdir().unwrap();
        let db = DB::new(tempdir.path(), true).unwrap();
        (db, tempdir)
    }

    pub fn log_to_stdout(level: Option<LevelFilter>) {
        let level = level.unwrap_or_else(|| LevelFilter::max());
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
