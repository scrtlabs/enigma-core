
use url::{Url};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {

    /// Run info mode and shutdown. (Not actually running the node)
    #[structopt(short = "i", long = "info")]
    pub info: bool,

    /// Deploy the Enigma contract related infrastructure 
    #[structopt(short = "d", long = "deploy")]
    pub deploy: bool,
    
    /// Deploy to a different network (not the localhost:port)
    #[structopt(short = "n", long = "network" , default_value ="http://.c")]
    pub network: Url,
       
}

pub fn print_info(){

}
pub fn test() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    println!("info => {}", opt.info);
    println!("deploy {}", opt.deploy);
    println!("network {}", opt.network);
}