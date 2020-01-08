extern crate enigma_core_app;
#[macro_use]
extern crate log;
extern crate log_derive;

use log::{debug, info};

use std::str::FromStr;

pub use enigma_core_app::*;
pub use esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_update_state, ocall_remove_delta};

pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
use enigma_tools_u::common_u::logging;
use enigma_tools_u::common_u::os;

use networking::{ipc_listener, IpcListener};
use db::DB;
use cli::Opt;
use structopt::StructOpt;
use futures::Future;


fn main() {
    let opt: Opt = Opt::from_args();

    let log_level = log::LevelFilter::from_str(&opt.log_level).unwrap();

    let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap().join(".enigma"));
    let hostname = os::hostname();
    let _handler = logging::init_logger(log_level, &datadir, hostname);

    debug!("CLI params: {:?}", opt);


    let enclave = esgx::general::init_enclave_wrapper().map_err(|e| {error!("Init Enclave Failed {:?}", e);}).unwrap();
    let eid = enclave.geteid();
    info!("Init Enclave Successful. Enclave id {}", eid);

    let mut db = DB::new(datadir, true).expect("Failed initializing the DB");
    let server = IpcListener::new(&format!("tcp://*:{}", opt.port));

    server
        .run(move |multi| ipc_listener::handle_message(&mut db, multi, &opt.spid, eid, opt.retries))
        .wait()
        .unwrap();
}