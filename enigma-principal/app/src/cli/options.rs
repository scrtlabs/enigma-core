use structopt::StructOpt;
use url::Url;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {
    /// Run info mode and shutdown. (Not actually running the node)
    #[structopt(short = "i", long = "info")]
    pub info: bool,

    /// Output the signing address only
    #[structopt(short = "w", long = "write-sign-address")]
    pub sign_address: bool,

    /// Run the Register procedure and shutdown
    #[structopt(short = "r", long = "register")]
    pub register: bool,

    /// Run the Set Worker Params procedure and shutdown
    #[structopt(short = "p", long = "set-worker-params")]
    pub set_worker_params: bool,

    /// Confirm the Worker Params in the local state and shutdown
    #[structopt(short = "f", long = "confirm-worker-params")]
    pub confirm_worker_params: bool,

    /// Get state keys and shutdown
    #[structopt(short = "k", long = "get-state-keys")]
    pub get_state_keys: Option<String>,

    /// Optional: The Enigma contract address, use the config if not provided
    #[structopt(short = "c", long = "contract-address")]
    pub contract_address: Option<String>,

    /// Optional: Reset the Epoch state in storage
    #[structopt(short = "s", long = "reset-epoch-state")]
    pub reset_epoch_state: bool,

    /// Optional: Deploy the Enigma contract related infrastructure
    #[structopt(short = "d", long = "deploy")]
    pub deploy: bool,

    /// Optional currently ignored: Deploy to a different network (not the localhost:port)
    #[structopt(short = "n", long = "network", default_value = "http://.c")]
    pub network: Url,

    /// Optional: simulate blocks mining --mine <>
    #[structopt(short = "m", long = "mine", default_value = "0")]
    pub mine: usize,

    /// Optional: how many loops to perform (seconds) for the principal in time (TTL)
    #[structopt(short = "x", long = "time-to-live", default_value = "0")]
    pub time_to_live: usize,

    /// Optional: if --deploy then change default to custom config file
    #[structopt(short = "y", long = "deploy-config", default_value = "../app/tests/principal_node/config/deploy_config.json")]
    pub deploy_config: String,

    /// Optional: change the default principal node config
    #[structopt(short = "z", long = "principal-config", default_value = "../app/tests/principal_node/config/principal_test_config.json")]
    pub principal_config: String,

    /// Optional: change the minimum log level
    #[structopt(short = "l", long = "log-level", default_value = "info")]
    pub log_level: String,
}

// fn all_colours() {
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
pub fn print_info(signing_address: &str, ethereum_address: &str) {
    print_logo();
    yellow!("<>------------------------------------------<>\n");
    green!("--info                                 => Print the signing address and help.\n");
    green!("--verbose                              => Verbosity of the log output (up to 5 -vvvvv).\n");
    green!("--debug-stdout                         => Print the debugging directly to stdout.\n");
    green!("--write-sign-address                   => Write the signing address to ~/.enigma/principal-sign-addr.txt.\n");
    green!("--register                             => Run the Register procedure and shutdown.\n");
    green!("--set-worker-params                    => Run the Set Worker Params procedure and shutdown.\n");
    green!("--confirm-worker-params                => Confirm the Worker Params in the local state and shutdown.\n");
    green!("--get-state-keys                       => Get the state keys from the message and shutdown.\n");
    green!("--contract-address                     => The Enigma contract address, use the config if not provided.\n");
    green!("--reset-epoch-state                    => Optional: Reset the Epoch state in storage.\n");
    green!("--deploy                               => Optional, deploy the Enigma contract.\n");
    green!("--network                              => Currently ignored, use a custom network (use config file instead).\n");
    green!("--mine <speed>                         => Optional, simulate new blocks, speed = seconds interval.\n");
    green!("--time-to-live <time>                  => Optional, kill the principal node after aprox <time> seconds.\n");
    green!("--deploy-config <path from current>    => Optional, if --deploy load deployment config from custom path.\n");
    green!("--principal-config <path from current> => Optional, load the principal config from custom path.\n");
    yellow!("<>------------------------------------------<>\n");
    red!("Enigma address                  => 0x{}\n", signing_address);
    red!("Ethereum address                => 0x{}\n", ethereum_address);
    yellow!("<>------------------------------------------<>\n");
}
