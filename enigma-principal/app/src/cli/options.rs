use structopt::StructOpt;
use url::Url;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {

    /// Output the signing address only
    #[structopt(short = "w", long = "write-sign-address")]
    pub sign_address: bool,

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
