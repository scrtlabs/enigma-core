//! # Enigma Core CLI.
//!
//! We use `StructOpt` to easily generate the CLI https://github.com/TeXitoi/structopt <br>
//! it uses rustdocs for the `--help` menu, and proc macros to get long/short and parsing methods. <br>
//! it is used by running `let opt: Opt = Opt::from_args();` and thn it will fill up the struct from the user inputs.
//! (and of course fail if needed)

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Enigma Core", about = "Enigma Core CLI commands.")]
pub struct Opt {
    /// Increase verbosity of messages (up to 5 -vvvvv)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbose: u8,
    /// Print the debugging directly to stdout
    #[structopt(long = "debug-stdout")]
    pub debug_stdout: bool,
    /// Specify data directory
    #[structopt(parse(from_os_str), long = "data-dir")]
    pub data_dir: Option<PathBuf>,
    /// Specify a different SPID to use for the Quote/Report
    #[structopt(long = "spid", default_value = "B0335FD3BC1CCA8F804EB98A6420592D")]
    pub spid: String,
    /// Select a port for the enigma-p2p listener
    #[structopt(long = "port", short = "p", default_value = "5552")]
    pub port: u16,
}