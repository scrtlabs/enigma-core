//! # Enigma Core CLI.
//!
//! We use `StructOpt` to easily generate the CLI https://github.com/TeXitoi/structopt <br>
//! it uses rustdocs for the `--help` menu, and proc macros to get long/short and parsing methods. <br>
//! it is used by running `let opt: Opt = Opt::from_args();` and then it will fill up the struct from the user inputs.
//! (and of course fail if needed)

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Enigma Core", about = "Enigma Core CLI commands.")]
pub struct Opt {
    /// Specify data directory
    #[structopt(parse(from_os_str), long = "data-dir")]
    pub data_dir: Option<PathBuf>,
    /// Specify a different SPID to use for the Quote/Report
    #[structopt(long = "spid", default_value = "B0335FD3BC1CCA8F804EB98A6420592D")]
    pub spid: String,
    /// Select a port for the enigma-p2p listener
    #[structopt(long = "port", short = "p", default_value = "5552")]
    pub port: u16,
    /// Specify the number of Attestation call retries when failing
    #[structopt(long = "retries", short = "r", default_value = "10")]
    pub retries: u32,
    /// Optional: change the minimum log level
    #[structopt(short = "l", long = "log-level", default_value = "info")]
    pub log_level: String,
}