use std::sync::atomic::AtomicU64;
use boot_network::deploy_scripts;
use boot_network::principal_utils::Principal;
use boot_network::keys_provider_http::PrincipalHttpServer;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::esgx::equote::retry_quote;
use enigma_tools_u::web3_utils::enigma_contract::{ContractFuncs, EnigmaContract};
use esgx;
use failure::Error;
use serde_derive::*;
use serde_json;
use sgx_types::sgx_enclave_id_t;
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;
use std::thread;
use web3::transports::Http;
use web3::types::{Address, U256};
use web3::Web3;
use boot_network::epoch_provider::EpochProvider;


#[derive(Serialize, Deserialize, Debug)]
pub struct PrincipalConfig {
    pub enigma_contract_path: String,
    pub enigma_contract_remote_path: String,
    pub enigma_contract_address: String,
    pub account_address: String,
    pub test_net: bool,
    pub with_private_key: bool,
    pub private_key: String,
    pub url: String,
    pub epoch_size: usize,
    pub polling_interval: u64,
    pub max_epochs: Option<usize>,
    pub spid: String,
    pub attestation_service_url: String,
    pub http_port: String,
}

impl PrincipalConfig {
    pub fn set_enigma_contract_address(&mut self, new_address: String) { self.enigma_contract_address = new_address; }
    pub fn set_accounts_address(&mut self, new_account: String) { self.account_address = new_account; }
    pub fn set_ethereum_url(&mut self, ethereum_url: String) { self.url = ethereum_url; }
}

pub struct PrincipalManager {
    pub config: PrincipalConfig,
    as_service: service::AttestationService,
    pub contract: Arc<EnigmaContract>,
    pub eid: sgx_enclave_id_t,
}

impl PrincipalManager {
    // load json config into the struct
    pub fn load_config(config_path: &str) -> Result<PrincipalConfig, Error> {
        println!("Loading Principal config: {:?}", config_path);
        let mut f = File::open(config_path)?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(serde_json::from_str(&contents)?)
    }

    pub fn get_web3(&self) -> Arc<Web3<Http>> { Arc::clone(&self.contract.web3) }
}

// General interface of a Sampler == The entity that manages the principal node logic.
pub trait Sampler {
    /// load with config from file
    fn new(config_path: &str, contract: Arc<EnigmaContract>, eid: sgx_enclave_id_t) -> Result<Self, Error>
        where Self: Sized;

    /// load with config passed from the caller (for mutation purposes)
    fn new_delegated(config: PrincipalConfig, contract: Arc<EnigmaContract>, eid: sgx_enclave_id_t) -> Self;

    fn get_contract_address(&self) -> Address;

    fn get_quote(&self) -> Result<String, Error>;

    fn get_report(&self, quote: &str) -> Result<(Vec<u8>, String, service::ASResponse), Error>;

    fn get_signing_address(&self) -> Result<String, Error>;

    fn get_account_address(&self) -> Address;

    fn get_network_url(&self) -> String;

    /// after initiation, this will run the principal node and block.
    fn run<G: Into<U256>>(&self, gas: G) -> Result<(), Error>;
}

impl Sampler for PrincipalManager {
    fn new(config_path: &str, contract: Arc<EnigmaContract>, eid: sgx_enclave_id_t) -> Result<Self, Error> {
        let config = PrincipalManager::load_config(config_path)?;
        Ok(Self::new_delegated(config, contract, eid))
    }

    fn new_delegated(config: PrincipalConfig, contract: Arc<EnigmaContract>, eid: sgx_enclave_id_t) -> Self {
        let as_service = service::AttestationService::new(&config.attestation_service_url);
        PrincipalManager { eid, config, as_service, contract }
    }

    fn get_contract_address(&self) -> Address { self.contract.address() }

    fn get_quote(&self) -> Result<String, Error> { Ok(retry_quote(self.eid, &self.config.spid, 18)?) }

    fn get_report(&self, quote: &str) -> Result<(Vec<u8>, String, service::ASResponse), Error> {
        let (rlp_encoded, as_response) = self.as_service.rlp_encode_registration_params(quote)?;
        let signature = as_response.result.signature.clone();
        Ok((rlp_encoded, signature, as_response))
    }

    fn get_signing_address(&self) -> Result<String, Error> {
        let mut signing_address = esgx::equote::get_register_signing_address(self.eid)?;
        // remove 0x
        signing_address = signing_address[2..].to_string();
        Ok(signing_address)
    }

    fn get_account_address(&self) -> Address { self.contract.account.clone() }

    fn get_network_url(&self) -> String { self.config.url.clone() }

    fn run<G: Into<U256>>(&self, gas_limit: G) -> Result<(), Error> {
        // get quote
        let quote = self.get_quote()?;
        // get report
        let (rlp_encoded, signature, _) = self.get_report(&quote)?;
        // get enigma contract
        let enigma_contract = &self.contract;
//        let enigma_contract = &self.contract;
        let gas_limit: U256 = gas_limit.into();
        // register worker
        //0xc44205c3aFf78e99049AfeAE4733a3481575CD26
        let signer = self.get_signing_address()?;
        println!("Registering Principal node with signing address = {}", signer);
        let tx = enigma_contract.register(&signer, &rlp_encoded, &signature, gas_limit)?;
        println!("Registered worker with tx: {:?}", tx);

        // Start the WorkerParameterized Web3 log filter
        let eid = Arc::new(AtomicU64::new(self.eid));
        let em = Arc::new(EpochProvider::new(Arc::clone(&eid), self.contract.clone()));
        thread::spawn(move || {
            println!("Starting the worker parameters watcher in child thread");
            em.filter_worker_params();
        });

        // Start the JSON-RPC Server
        let port = self.config.http_port.clone();
        thread::spawn(move || {
            println!("Starting the JSON RPC Server");
            let server = PrincipalHttpServer::new(eid, &port);
            server.start();
        });

        // watch blocks
        let polling_interval = self.config.polling_interval;
        let epoch_size = self.config.epoch_size;
        enigma_contract.watch_blocks(epoch_size, polling_interval, self.eid, gas_limit, self.config.max_epochs);
        Ok(())
    }
}

/// Helper method to start 'miner' that simulates blocks.
pub fn run_miner(account: Address, w3: Arc<Web3<Http>>, interval: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        deploy_scripts::forward_blocks(&Arc::clone(&w3), interval, account).unwrap();
    })
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use boot_network::deploy_scripts;
    use enigma_crypto::hash::Keccak256;
    use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
    use enigma_tools_u::web3_utils::w3utils;
    use esgx::general::init_enclave_wrapper;
    use rustc_hex::ToHex;
    use std::sync::Arc;
    use std::{env, thread, time};
    use web3::transports::Http;
    use web3::types::{Log, H256};
    use web3::Web3;

    /// This function is important to enable testing both on the CI server and local.
    /// On the CI Side:
    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
    /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:8545")) }

    /// helps in assertion to check if a random event was indeed broadcast.
    pub fn filter_random(w3: &Arc<Web3<Http>>, contract_addr: Option<&str>, event_name: &str)
                         -> Result<Vec<Log>, Error> {
        let logs = w3utils::filter_blocks(&w3, contract_addr, event_name)?;
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
        let enclave = init_enclave_wrapper().unwrap();

        let eid = enclave.geteid();
        // load the config
        let deploy_config = "../app/tests/principal_node/config/deploy_config.json";
        let mut config = deploy_scripts::load_config(deploy_config).unwrap();
        // modify to dynamic address
        //        config.set_accounts_address(deployer);
        config.set_ethereum_url(get_node_url());

        let signer_addr = deploy_scripts::get_signing_address(eid).unwrap();
        // deploy all contracts. (Enigma & EnigmaToken)
        let enigma_contract = Arc::new(EnigmaContract::deploy_contract(&config.enigma_token_contract_path,
                                                                       &config.enigma_contract_path,
                                                                       &config.url,
                                                                       None,
                                                                       &signer_addr).expect("cannot deploy Enigma,EnigmaToken"));

        let account = enigma_contract.account.clone();

        // run simulated miner
        run_miner(account, Arc::clone(&enigma_contract.web3), 1);

        let principal_config = "../app/tests/principal_node/config/principal_test_config.json";
        let mut the_config = PrincipalManager::load_config(principal_config).unwrap();
        the_config.set_accounts_address(account.to_hex());
        the_config.set_enigma_contract_address(enigma_contract.address().to_hex());
        the_config.set_ethereum_url(get_node_url());

        // run event filter in the background
        let event_name = "WorkersParameterized(uint256,address[],bool)";
        let w3 = Arc::clone(&enigma_contract.web3);
        let child = thread::spawn(move || {
            let mut counter = 0;
            loop {
                counter += 1;
                let logs = filter_random(&Arc::clone(&w3), None, &event_name).expect("err filtering random");
                // the test: if events recieved >2 (more than 2 emitts of random)
                // assert topic (keccack(event_name))
                if logs.len() >= 2 {
//                    println!("FOUND 2 LOGS!!!! {:?}", logs);
                    for log in logs.iter() {
                        let expected_topic = event_name.as_bytes().keccak256();
                        assert!(log.topics[0].contains(&H256::from_slice(&*expected_topic)));
                    }
                    break;
                }
                thread::sleep(time::Duration::from_secs(1));
                let max_time = 30;
                if counter > max_time {
                    panic!("test failed, more than {} seconds without events", max_time)
                }
            }
        });

        // run principal
        let principal = PrincipalManager::new_delegated(the_config, enigma_contract, eid);
        principal.run(5999999).unwrap();
        child.join().unwrap();
    }
}
