//! # Enigma Core Logging.
//!
//! For logs we use the official `log` facade (https://github.com/rust-lang-nursery/log) <br>
//! This module returns loggers according to the inputs (a file logger and a stdout logger) <br>
//! they catch the logs themselves from the `log` facade. <br>
//! Default verbosity for stdout logger is `Error` and each verbose level will increase it accordingly. <br>
//! Default verbosity for the file logger is `Warn` and it's always one level above the stdout logger. <br>


use std::{fs::{self, File}, path::Path};
use failure::Error;
use log::LevelFilter;
use simplelog::{SharedLogger, WriteLogger};
pub use simplelog::{CombinedLogger, TermLogger};

pub fn get_logger<P: AsRef<Path>>(stdout: bool, data_dir: P, verbose: u8) ->  Result<Vec<Box<dyn SharedLogger>>, Error> {
    let file_level = log_level_from_verbose(verbose + 2); // This plus 2 means that by default it logs from Warn level and up

    // Make sure the directory exist.
    fs::create_dir_all(&data_dir)?;

    let mut debug_path = data_dir.as_ref().to_path_buf();
    debug_path.push("debug.log");
    let file = File::create(debug_path)?;

    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::with_capacity(2);
    let config = simplelog::Config::default();
    let file_log = WriteLogger::new(file_level, config, file);
    loggers.push(file_log);
    if stdout {
        let stdout_level = log_level_from_verbose(verbose + 1); // The plus one means even with no verbose errors will be printed to stdout.
        let term_logger = TermLogger::new(stdout_level, config).ok_or_else(|| format_err!("Failed loading TermLogger"))?;
        loggers.push(term_logger);
    }
    Ok(loggers)
}

fn log_level_from_verbose(u: u8) -> LevelFilter {
    match u {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 | _ => LevelFilter::Trace,
    }
}
