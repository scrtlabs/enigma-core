use structopt::StructOpt;
use url::Url;
use std::env;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {
    /// Run info mode and shutdown. (Not actually running the node)
    #[structopt(short = "i", long = "info")]
    pub info: bool,

    /// Output the signing address only
    #[structopt(short = "s", long = "write-sign-address")]
    pub sign_address: Option<String>,

    /// Run the Register procedure and shutdown
    #[structopt(short = "r", long = "register")]
    pub register: bool,

    /// Run the Set Worker Params procedure and shutdown
    #[structopt(short = "sw", long = "set-worker-params")]
    pub set_worker_params: bool,

    /// Optional: Deploy the Enigma contract related infrastructure
    #[structopt(short = "d", long = "deploy")]
    pub deploy: bool,

    ///Optional currently ignored: Deploy to a different network (not the localhost:port)
    #[structopt(short = "n", long = "network", default_value = "http://.c")]
    pub network: Url,

    /// Optional: simulate blocks mining --mine <>
    #[structopt(short = "m", long = "mine", default_value = "0")]
    pub mine: usize,

    /// Optional: how many loops to perform (seconds) for the principal in time (TTL)
    #[structopt(short = "ttl", long = "time-to-live", default_value = "0")]
    pub time_to_live: usize,

    /// Optional: if --deploy then change default to custom config file
    #[structopt(short = "dc", long = "deploy-config", default_value = "../app/tests/principal_node/config/deploy_config.json")]
    pub deploy_config: String,

    /// Optional: change the default principal node config
    #[structopt(short = "pc", long = "principal-config", default_value = "../app/tests/principal_node/config/principal_test_config.json")]
    pub principal_config: String,
}

//fn all_colours() {
//    black!("black ");
//    red!("red ");
//    green!("green ");
//    yellow!("yellow ");
//    blue!("blue ");
//    magenta!("magenta ");
//    cyan!("cyan ");
//    white!("white ");
//    dark_black!("dark_black ");
//    dark_red!("dark_red ");
//    dark_green!("dark_green ");
//    dark_yellow!("dark_yellow ");
//    dark_blue!("dark_blue ");
//    dark_magenta!("dark_magenta ");
//    dark_cyan!("dark_cyan ");
//    dark_white!("dark_white ");
//    prnt!("default colour\n\n");
//}

pub fn print_logo() {
    yellow!("<>------------------------------------------<>\n");
    magenta!(
             "
\t╔═╗ ┌┐┌ ┬ ┌─┐ ┌┬┐ ┌─┐
\t║╣  │││ │ │ ┬ │││ ├─┤
\t╚═╝ ┘└┘ ┴ └─┘ ┴ ┴ ┴ ┴ \n
\t╔═╗ ┬─┐ ┬ ┌┐┌ ┌─┐ ┬ ┌─┐ ┌─┐ ┬
\t╠═╝ ├┬┘ │ │││ │   │ ├─┘ ├─┤ │
\t╩   ┴└─ ┴ ┘└┘ └─┘ ┴ ┴   ┴ ┴ ┴─┘\n
\t╔╗╔ ┌─┐ ┌┬┐ ┌─┐
\t║║║ │ │  ││ ├┤
\t╝╚╝ └─┘ ─┴┘ └─┘\n"
    );
    yellow!("<>------------------------------------------<>\n");
}
pub fn print_info(sign_key: &str) {
    print_logo();
    yellow!("<>------------------------------------------<>\n");
    green!("--info                                 => Print the signing address and help.\n");
    green!("--write-sign-address <path>            => Write the signing address to the specified file.\n");
    green!("--register                             => Run the Register procedure and shutdown.\n");
    green!("--set-worker-params                    => Run the Set Worker Params procedure and shutdown.\n");
    green!("--deploy                               => Optional, deploy the Enigma contract.\n");
    green!("--network                              => Currently ignored, use a custom network (use config file instead).\n");
    green!("--mine <speed>                         => Optional, simulate new blocks, speed = seconds interval.\n");
    green!("--time-to-live <time>                  => Optional, kill the principal node after aprox <time> seconds.\n");
    green!("--deploy-config <path from current>    => Optional, if --deploy load deployment config from custom path.\n" );
    green!("--principal-config <path from current> => Optional, load the principal config from custom path.\n");
    yellow!("<>------------------------------------------<>\n");
    red!("Enclave Signing address                => 0x{}\n", sign_key);
    yellow!("<>------------------------------------------<>\n");
}
