//! # Enigma Core Logging.
//!
//! For logs we use the official `log` facade (https://github.com/rust-lang-nursery/log) <br>
//! This module returns loggers according to the inputs (a file logger and a stdout logger) <br>
//! they catch the logs themselves from the `log` facade. <br>
//! Default verbosity for stdout logger is `Error` and each verbose level will increase it accordingly. <br>
//! Default verbosity for the file logger is `Warn` and it's always one level above the stdout logger. <br>


use std::{fs::{self}, path::Path};
use failure::Error;

use log::{LevelFilter};
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::{file::FileAppender, rolling_file::RollingFileAppender};
use log4rs::config::{Appender, Config, Root, Logger};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::Handle;
use log4rs::append::rolling_file::policy::compound::{trigger::size::SizeTrigger, roll::fixed_window::FixedWindowRoller, CompoundPolicy};

pub fn init_logger<P: AsRef<Path>>(level: log::LevelFilter, data_dir: P, name: String) -> Result<Handle, Error> {

    // Make sure the directory exists.
    fs::create_dir_all(&data_dir)?;
    let mut file_path = data_dir.as_ref().to_path_buf();
//    file_path.push("debug.{}.log");

    let mut foo = "[{d(%Y-%m-%d %H:%M:%S)}] [".to_string();
    foo.push_str(&name);
    foo.push_str("] {h({l:5.15})} {M} -- {m}{n}");
    // Build a stderr logger.
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(&foo)))
        .target(Target::Stdout).build();

    let window_size = 3;
    let pattern = file_path.clone().into_os_string().into_string().unwrap() + "/debug.{}.log";
    let fixed_window_roller =
        FixedWindowRoller::builder().build(&pattern ,window_size).unwrap();

    let size_limit = 5 * 1024; // 5KB as max log file size to roll
    let size_trigger = SizeTrigger::new(size_limit);

    let compound_policy = CompoundPolicy::new(Box::new(size_trigger),Box::new(fixed_window_roller));

    file_path.push("debug.log");
    // Logging to log file.
    let logfile = RollingFileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(PatternEncoder::new("[{d(%Y-%m-%d %H:%M:%S)}] [{t}] {l:5.15} {M} -- {m}{n}")))
        .build(file_path, Box::new(compound_policy))
        .unwrap();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stderr.
    // `logger` is used to define a log level for a crate used by the project.
    // we want to avoid unnecessary logs so defining the following with a high level.
    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .appender(Appender::builder()
                      .filter(Box::new(ThresholdFilter::new(level)))
                      .build("stderr", Box::new(stdout)))
        .logger(Logger::builder().build("tokio_zmq", LevelFilter::Warn))
        .logger(Logger::builder().build("hyper", LevelFilter::Warn))
        .logger(Logger::builder().build("tokio_reactor", LevelFilter::Warn))
        .logger(Logger::builder().build("tokio_core", LevelFilter::Warn))
        .logger(Logger::builder().build("web3", LevelFilter::Warn))
        .logger(Logger::builder().build("tokio_threadpool", LevelFilter::Warn))
        .logger(Logger::builder().build("want", LevelFilter::Warn))
        .build(Root::builder().appender("logfile").appender("stderr").build(LevelFilter::Trace))
        .unwrap();

    // Use this to change log levels at runtime.
    // This means you can change the default log level to trace
    // if you are trying to debug an issue and need more logs on, then turn it off
    // once you are done.
    let handle = log4rs::init_config(config).unwrap();
    Ok(handle)
}


#[cfg(test)]
mod test {
    use super::*;
    use log::LevelFilter;

    #[test]
    fn test_the_rolling_logger() {
        let log_level = LevelFilter::Debug;
        let datadir = dirs::home_dir().unwrap().join(".enigma");

        init_logger(log_level, datadir, "what".to_string());
        let mut n = 1;
        while n < 250 {
            info!("{:?}_83a464617461a752657175657374a269649cccd763674174cc9b3f300dccd2ccb0cc8ba67075626b6579dc0040ccc90b2205ccf9cc9358661320ccffccb763ccb57614ccf8ccaa1fccb86d6a087869ccd81acce5ccf16fcc9206cc98344136cca4ccefccb105ccbbccca1c5057ccba25067eccc101cc82ccee21445cccf91e79ccb176447239", n);
            n += 1;
        }
    }
}