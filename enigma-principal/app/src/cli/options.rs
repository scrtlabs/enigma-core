
use url::{Url};
use std::path::PathBuf;
use structopt::StructOpt;
use web3::types::{Address, U256, Bytes,Log};
use boot_network::deploy_scripts;
use enigma_tools_u::web3_utils::w3utils;
use std::thread;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {
    
    /// Run info mode and shutdown. (Not actually running the node)
    #[structopt(short = "i", long = "info")]
    pub info: bool,

    /// Optional: Deploy the Enigma contract related infrastructure 
    #[structopt(short = "d", long = "deploy")]
    pub deploy: bool,
    
    ///Optional currently ignored: Deploy to a different network (not the localhost:port)
    #[structopt(short = "n", long = "network" , default_value ="http://.c")]
    pub network: Url,


    /// Optional: simulate blocks mining --mine <>
    #[structopt(short = "m", long = "mine", default_value = "0")]
    pub mine: usize,

    /// Optional: how many loops to perform (seconds) for the principal in time (TTL)
    #[structopt(short = "ttl", long = "time-to-live", default_value = "0")]
    pub time_to_live: usize,

    /// Optional: if --deploy then change default to custom config file 
    #[structopt(short = "dc", long = "deploy-config", default_value = "../app/tests/principal_node/contracts/deploy_config.json")]
    pub deploy_config: String,

    /// Optional: change the default principal node config  
    #[structopt(short = "pc", long = "principal-config", default_value = "../app/tests/principal_node/contracts/principal_test_config.json")]
    pub principal_config: String,
    
}

pub fn run_miner(url : String ,accounts : &Vec<Address>, mining_interval : usize ){
    let deployer : String = w3utils::address_to_string_addr(&accounts[0]);
    let child = thread::spawn(move || {
        deploy_scripts::forward_blocks
        (
            mining_interval as u64,
            deployer, 
            url.to_string()
        );
    });
}

fn all_colours() {
    black!("black ");
    red!("red ");
    green!("green ");
    yellow!("yellow ");
    blue!("blue ");
    magenta!("magenta ");
    cyan!("cyan ");
    white!("white ");
    dark_black!("dark_black ");
    dark_red!("dark_red ");
    dark_green!("dark_green ");
    dark_yellow!("dark_yellow ");
    dark_blue!("dark_blue ");
    dark_magenta!("dark_magenta ");
    dark_cyan!("dark_cyan ");
    dark_white!("dark_white ");
    prnt!("default colour\n\n");
}

pub fn print_logo(){
yellow!("<>------------------------------------------<>\n");
magenta!("
\t╔═╗ ┌┐┌ ┬ ┌─┐ ┌┬┐ ┌─┐         
\t║╣  │││ │ │ ┬ │││ ├─┤         
\t╚═╝ ┘└┘ ┴ └─┘ ┴ ┴ ┴ ┴ \n        
\t╔═╗ ┬─┐ ┬ ┌┐┌ ┌─┐ ┬ ┌─┐ ┌─┐ ┬    
\t╠═╝ ├┬┘ │ │││ │   │ ├─┘ ├─┤ │    
\t╩   ┴└─ ┴ ┘└┘ └─┘ ┴ ┴   ┴ ┴ ┴─┘\n
\t╔╗╔ ┌─┐ ┌┬┐ ┌─┐             
\t║║║ │ │  ││ ├┤              
\t╝╚╝ └─┘ ─┴┘ └─┘\n");
yellow!("<>------------------------------------------<>\n");
}
pub fn print_info(sign_key : &str){
    print_logo();
    yellow!("<>------------------------------------------<>\n");
    green!("--info                                 => Print the signing key and help.\n");
    green!("--deploy                               => Optional, deploy the Enigma contract.\n" );
    green!("--network                              => Currently ignored, use a custom network (use config file instead).\n" );
    green!("--mine <speed>                         => Optional, simulate new blocks, speed = seconds interval.\n" );
    green!("--time-to-live <time>                  => Optional, kill the principal node after aprox <time> seconds.\n" );
    green!("--deploy-config <path from current>    => Optional, if --deploy load deployment config from custom path.\n" );
    green!("--principal-config <path from current> => Optional, load the principal config from custom path.\n" );
    yellow!("<>------------------------------------------<>\n");
    red!("Enclave Signing address                => 0x{}\n", sign_key);
    yellow!("<>------------------------------------------<>\n");
}


pub fn test() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    println!("info => {}", opt.info);
    println!("deploy {}", opt.deploy);
    println!("network {}", opt.network);
    println!("mine {}", opt.mine);
    println!("time to live  {}", opt.time_to_live);
}