extern crate enigma_core_app;
#[macro_use]
extern crate log;
extern crate log_derive;
extern crate log4rs;

use log::{debug, error, info, trace, warn};
use log::{LevelFilter, SetLoggerError};
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;

pub use enigma_core_app::*;
pub use esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_update_state, ocall_remove_delta};
pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
use enigma_tools_u::common_u::logging;
use networking::{ipc_listener, IpcListener};
use db::DB;
use cli::Opt;
use structopt::StructOpt;
use futures::Future;
use simplelog::CombinedLogger;


fn main() {
    let level = log::LevelFilter::Info;
    let file_path = "/tmp/foo.log";

    // Build a stderr logger.
    let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

    // Logging to log file.
    let logfile = FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
        .build(file_path)
        .unwrap();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stderr.
    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(LevelFilter::Trace),
        )
        .unwrap();

    // Use this to change log levels at runtime.
    // This means you can change the default log level to trace
    // if you are trying to debug an issue and need more logs on then turn it off
    // once you are done.
    let _handle = log4rs::init_config(config).unwrap();


    let opt: Opt = Opt::from_args();
    debug!("CLI params: {:?}", opt);

    let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap().join(".enigma"));
    // let loggers = logging::get_logger(opt.debug_stdout, datadir.clone(), opt.verbose).expect("Failed Creating the loggers");
    // CombinedLogger::init(loggers).expect("Failed initializing the logger");

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