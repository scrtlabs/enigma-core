#[macro_use]
extern crate structopt;

use std::path::PathBuf;
use structopt::StructOpt;


/// A basic example
#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Opt {
    // A flag, true if used in the command line. Note doc comment will
    // be used for the help message of the flag.
    /// Activate debug mode
    #[structopt(short = "d", long = "debug")]
    debug: bool,

    // The number of occurences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: u8,

    /// Set speed
    #[structopt(short = "s", long = "speed", default_value = "42")]
    speed: f64,

    /// Output file
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    output: PathBuf,

    /// Number of cars
    #[structopt(short = "c", long = "nb-cars")]
    nb_cars: Option<i32>,

    /// admin_level to consider
    #[structopt(short = "l", long = "level")]
    level: Vec<String>,

    /// Files to process
    #[structopt(name = "FILE", parse(from_os_str))]
    files: Vec<PathBuf>,
}
