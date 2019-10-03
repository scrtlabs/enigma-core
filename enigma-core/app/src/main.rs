extern crate enigma_core_app;

#[macro_use]
extern crate log;
extern crate log_derive;

pub use enigma_core_app::*;
pub use esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_update_state};
pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
use enigma_tools_u::common_u::logging;
use networking::{ipc_listener, IpcListener};
use db::DB;
use cli::Opt;
use structopt::StructOpt;
use futures::Future;
use simplelog::CombinedLogger;

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

    server
        .run(move |multi| ipc_listener::handle_message(&mut db, multi, &opt.spid, eid, opt.retries))
        .wait()
        .unwrap();
}