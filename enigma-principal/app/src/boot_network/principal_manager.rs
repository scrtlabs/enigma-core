#![allow(non_snake_case)]

//sgx
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use esgx;
// general
use rlp;
use enigma_tools_u;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::attestation_service::service::*;
use enigma_tools_u::attestation_service::constants;
use failure::Error;
//web3
use web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use web3::types::FilterBuilder;
use web3::transports::Http;
use web3::Web3;
// tokio+polling blocks
use rustc_hex::FromHex;
use tokio_core;
use std::time;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
// formal
use enigma_tools_u::web3_utils::enigma_contract;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::w3utils;
use enigma_tools_u::esgx::equote::retry_quote;
use boot_network::deploy_scripts;
use boot_network::principal_utils::Principal;
use boot_network::principal_utils::EmittParams;
use boot_network::principal_server::PrincipalHttpServer;

// files
use std::fs::File;
use std::io::prelude::*;
use serde_derive::*;
use serde_json;
use serde_json::Value;
use boot_network::principal_utils::emitter_builder;


#[derive(Serialize, Deserialize, Debug)]
pub struct PrincipalConfig {
    pub ENIGMA_CONTRACT_PATH: String,
    pub ENIGMA_CONTRACT_REMOTE_PATH: String,
    pub ENIGMA_CONTRACT_ADDRESS: String,
    pub ACCOUNT_ADDRESS: String,
    pub TEST_NET: bool,
    pub WITH_PRIVATE_KEY: bool,
    pub PRIVATE_KEY: String,
    pub URL: String,
    pub EPOCH_SIZE: usize,
    pub POLLING_INTERVAL: u64,
    pub SPID: String,
    pub ATTESTATION_SERVICE_URL: String,
    pub HTTP_PORT: String,
}

impl PrincipalConfig {
    pub fn set_enigma_contract_address(&mut self, new_address: String) {
        self.ENIGMA_CONTRACT_ADDRESS = new_address;
    }
    pub fn set_accounts_address(&mut self, new_account: String) {
        self.ACCOUNT_ADDRESS = new_account;
    }
    pub fn set_ethereum_url(&mut self, ethereum_url: String) {
        self.URL = ethereum_url;
    }
}

pub struct PrincipalManager {
    custom_contract_address: Option<Address>,
    config_path: String,
    pub config: PrincipalConfig,
    emitt_params: EmittParams,
    server: PrincipalHttpServer,
    as_service: service::AttestationService,
}

impl PrincipalManager {
    pub fn load_config(config_path: &str) -> PrincipalConfig {
        let mut f = File::open(config_path)
            .expect("file not found.");

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("canno't read file");

        serde_json::from_str(&contents).unwrap()
    }
}

/*
    General interface of a Sampler == The entity that manages the principal node logic.
*/
pub trait Sampler {
    /// load with config from file
    fn new(config: &str, emit: EmittParams, custom_contract_address: Option<Address>) -> Self;
    /// load with config passed from the caller (for mutation purposes)
    fn new_delegated(config_path: &str, emit: EmittParams, the_config: PrincipalConfig) -> Self;
    fn get_contract_address(&self) -> String;
    fn get_quote(&self) -> Result<String, Error>;
    fn get_report(&self, quote: &str) -> Result<(Vec<u8>, service::ASResponse), Error>;
    /// connect to the ethereum network
    fn connect(&self) -> Result<(web3::transports::EventLoopHandle, Web3<Http>), Error>;
    fn enigma_contract(&self, web3::transports::EventLoopHandle, Web3<Http>) -> Result<EnigmaContract, Error>;
    fn get_signing_address(&self) -> Result<String, Error>;
    fn get_account_address(&self) -> Result<Address, Error>;
    fn get_network_url(&self) -> String;
    // after initialization, start the HTTP server for the JSON RPC api
    fn start_server(&self) -> Result<(), Error>;
    /// after initiation, this will run the principal node and block.
    fn run(&self) -> Result<(), Error>;
}

impl Sampler for PrincipalManager {
    fn new(config_path: &str, emit: EmittParams, custom_contract_address: Option<Address>) -> Self {
        let config = PrincipalManager::load_config(config_path);
        let connection_str = config.ATTESTATION_SERVICE_URL.clone();
        let port_str = config.HTTP_PORT.clone();
        PrincipalManager {
            custom_contract_address,
            config_path: config_path.to_string(),
            config,
            emitt_params: emit,
            as_service: service::AttestationService::new(&connection_str),
            server: PrincipalHttpServer::new(&port_str),
        }
    }
    fn new_delegated(config_path: &str, emit: EmittParams, the_config: PrincipalConfig) -> Self {
        let config = the_config;
        let connection_str = config.ATTESTATION_SERVICE_URL.clone();
        let port_str = config.HTTP_PORT.clone();
        PrincipalManager {
            custom_contract_address: None,
            config_path: config_path.to_string(),
            config,
            emitt_params: emit,
            as_service: service::AttestationService::new(&connection_str),
            server: PrincipalHttpServer::new(&port_str),
        }
    }
    fn get_contract_address(&self) -> String {
        if self.custom_contract_address.is_none() {
            return self.config.ENIGMA_CONTRACT_ADDRESS.clone();
        } else {
            let addr = self.custom_contract_address.unwrap();
            return w3utils::address_to_string_addr(&addr);
        }
    }
    fn get_quote(&self) -> Result<String, Error> {
        let eid = self.emitt_params.eid;
        match retry_quote(eid, &self.config.SPID, 8) {
            Ok(quote) => {
                Ok(quote)
            }
            Err(e) => {
                Err(e)
            }
        }
    }
    fn get_report(&self, quote: &str) -> Result<(Vec<u8>, service::ASResponse), Error> {
        let (rlp_encoded, as_response) = self.as_service.rlp_encode_registration_params(quote)?;
        Ok((rlp_encoded, as_response))
    }
    fn connect(&self) -> Result<(web3::transports::EventLoopHandle, Web3<Http>), Error> {
        let (_eloop, http) = web3::transports::Http::new(&self.config.URL.clone())
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        Ok((_eloop, w3))
    }
    fn get_account_address(&self) -> Result<Address, Error> {
        Ok
            (
                self.config.ACCOUNT_ADDRESS
                    .clone()
                    .parse()
                    .expect("[-] error parsing account address")
            )
    }
    fn enigma_contract(&self, eloop: web3::transports::EventLoopHandle, web3: Web3<Http>) -> Result<EnigmaContract, Error> {
        // deployed contract address
        let address = self.get_contract_address();
        // path to the build file of the contract
        let path = self.config.ENIGMA_CONTRACT_PATH.clone();
        // the account owner that initializes
        let account = self.config.ACCOUNT_ADDRESS.clone();
        // the ethereum node url
        let url = self.config.URL.clone();
        let enigma_contract = Principal::new(web3, eloop, &address, path, &account, url);
        Ok(enigma_contract)
    }
    fn get_signing_address(&self) -> Result<String, Error> {
        let eid = self.emitt_params.eid;
        let mut signing_address = esgx::equote::get_register_signing_address(eid)?;
        // remove 0x
        signing_address = signing_address[2..].to_string();
        Ok(signing_address)
    }
    fn start_server(&self) -> Result<(), Error> {
        self.server.start();
        Ok(())
    }
    fn run(&self) -> Result<(), Error> {
        // get quote
        let quote = self.get_quote()?;
        // get report
        let (rlp_encoded, as_response) = self.get_report(&quote)?;
        // get enigma contract
        let (eloop, w3) = self.connect()?;
        let enigma_contract = Arc::new(self.enigma_contract(eloop, w3)?);
        // register worker
        //0xc44205c3aFf78e99049AfeAE4733a3481575CD26
        let signer = self.get_signing_address()?;
        println!("signing address = {}", signer);
        let gas_limit = &self.emitt_params.gas_limit;
        enigma_contract.register_as_worker(&signer, &rlp_encoded, &gas_limit)?;

        // watch blocks
        let polling_interval = self.config.POLLING_INTERVAL;
        let epoch_size = self.config.EPOCH_SIZE;
        let eid = self.emitt_params.eid;
        // TODO: start JSON-RPC server
//        println!("starting the JSON-RPC HTTP server2");
//        self.start_server();

        let child_contract = Arc::clone(&enigma_contract);
        let child = thread::spawn(move || {
            println!("starting the worker parameters watcher in child thread");
            child_contract.filter_worker_params();
        });

        println!("starting the block watcher");
        let gas_limit = gas_limit.clone();
        // TODO: refactor to Generators when available to avoid nesting of set_workers_params
        enigma_contract.watch_blocks(epoch_size, polling_interval, eid, gas_limit, self.emitt_params.max_epochs);
        Ok(())
    }
    fn get_network_url(&self) -> String {
        self.config.URL.clone()
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use boot_network::principal_manager;
    use boot_network::principal_manager::*;
    use enigma_tools_u::web3_utils::w3utils;
    use boot_network::deploy_scripts;
    use web3::types::{Log, H256};
    use esgx::general::init_enclave_wrapper;
    use std::env;

    /// This function is important to enable testing both on the CI server and local.
    /// On the CI Side:
    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
    /// The default is set to ganache cli "http://localhost:8545"
    fn get_node_url() -> String {
        env::var("NODE_URL").unwrap_or("http://localhost:8545".to_string())
    }

    fn connect() -> (web3::transports::EventLoopHandle, Web3<Http>, Vec<Address>) {
        let uri = get_node_url();
        let (eloop, w3) = w3utils::connect(&uri).unwrap();
        let accounts = w3.eth().accounts().wait().unwrap();
        (eloop, w3, accounts)
    }

    /// Helper method to start 'miner' that simulates blocks.
    pub fn run_miner(accounts: &Vec<Address>) {
        let deployer: String = w3utils::address_to_string_addr(&accounts[0]);
        let child = thread::spawn(move || {
            let url = get_node_url();
            deploy_scripts::forward_blocks(1, deployer, url);
        });
    }

    /// helps in assertion to check if a random event was indeed broadcast.
    pub fn filter_random(contract_addr: Option<&str>, url: &str, event_name: &str) -> Result<Vec<Log>, Error> {
        let logs = w3utils::filter_blocks(contract_addr, event_name, url)?;
        Ok(logs)
    }

    /// This test is more like a system-test than a unit-test.
    /// It is only dependent on an ethereum node running under the NODE_URL evn var or the default localhost:8545
    /// First it deploys all the contracts related (EnigmaToken, Enigma) and runs miner to simulate blocks.
    /// Second, it spawns a background thread to poll for events and searchses for the WorkersParameterized event.
    /// Then, the principal register (full process including quote) and then,
    ///  starts watching blocks and emits random with WorkersParameterized event.
    /// The testing is looking for atleast 2 emmits of the WorkersParameterized event and compares the event triggerd
    /// If the event name is different or if it takes more than 30 seconds then the test will fail.
    #[test]
    //#[ignore]
    fn test_full_principal_logic() {
        // init enclave

        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0, 1);
                return;
            }
        };

        let eid = enclave.geteid();
        let (eloop, w3, accounts) = connect();
        let deployer: String = w3utils::address_to_string_addr(&accounts[0]);
        // load the config
        let deploy_config = "../app/tests/principal_node/config/deploy_config.json";
        let mut config = deploy_scripts::load_config(deploy_config);
        // modify to dynamic address
        config.set_accounts_address(deployer);
        config.set_ethereum_url(get_node_url());
        // deploy all contracts. (Enigma & EnigmaToken)
        let (enigma_contract, enigma_token) = deploy_scripts::deploy_base_contracts_delegated
            (
                eid,
                config,
                None,
            )
            .expect("cannot deploy Enigma,EnigmaToken");

        // run simulated miner
        run_miner(&accounts);

        // build the config

        let mut params: EmittParams = EmittParams {
            eid: eid,
            gas_limit: String::from("5999999"),
            max_epochs: Some(5),
            ..Default::default()
        };

        let principal_config = "../app/tests/principal_node/config/principal_test_config.json";
        let mut the_config = PrincipalManager::load_config(principal_config);
        let deployer: String = w3utils::address_to_string_addr(&accounts[0]);
        let contract_addr: String = w3utils::address_to_string_addr(&enigma_contract.address());
        the_config.set_accounts_address(deployer);
        the_config.set_enigma_contract_address(contract_addr.clone());
        the_config.set_ethereum_url(get_node_url());
        let url = the_config.URL.clone();
        // run event filter in the background

        let event_name: String = String::from("WorkersParameterized(uint256,address[],bool)");
        let child = thread::spawn(move || {
            let mut counter = 0;

            loop {
                counter += 1;
                let logs = filter_random(Some(&contract_addr), &url, &event_name).expect("err filtering random");
                // the test: if events recieved >2 (more than 2 emitts of random)
                // assert topic (keccack(event_name))
                if logs.len() > 2 {
                    for (idx, log) in logs.iter().enumerate() {
                        let expected_topic = w3utils::to_keccak256(event_name.as_bytes());
                        assert!(log.topics[0].contains(&H256::from_slice(&expected_topic)));
                    }
                    break;
                }
                thread::sleep(time::Duration::from_secs(1));
                let max_time = 30;
                if counter > max_time {
                    println!("more than {} seconds without events", max_time);
                    assert!(false);
                    break;
                }
            }
        });

        // run principal
        let principal = PrincipalManager::new_delegated(principal_config, params, the_config);
        principal.run().unwrap();
    }
}
