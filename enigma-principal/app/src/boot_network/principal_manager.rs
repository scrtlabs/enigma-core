#![allow(non_snake_case)]
//sgx
use esgx;
// general
use enigma_tools_u::attestation_service::service;
use failure::Error;
//web3
use web3::futures::{Future, Stream};
use web3::types::{Address};
use web3::transports::Http;
use web3::Web3;
// tokio+polling blocks 
use rustc_hex::FromHex;
// formal
use enigma_tools_u::web3_utils::enigma_contract::{EnigmaContract, ContractFuncs};
use enigma_tools_u::web3_utils::w3utils;
use enigma_tools_u::esgx::equote::retry_quote;
use boot_network::principal_utils::Principal;
use boot_network::principal_utils::{EmitParams};

// files 
use std::fs::File;
use std::io::prelude::*;
use serde_derive::*;
use serde_json;


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
    pub spid: String,
    pub attestation_service_url: String,

}

impl PrincipalConfig {
    pub fn set_enigma_contract_address(&mut self,new_address : String){
        self.enigma_contract_address = new_address;
    }
    pub fn set_accounts_address(&mut self, new_account : String){
        self.account_address = new_account;
    }
    pub fn set_ethereum_url(&mut self, ethereum_url : String){
        self.url = ethereum_url;
    }
}

pub struct PrincipalManager {
    config_path : String,
    pub config : PrincipalConfig,
    emit_params: EmitParams,
    as_service : service::AttestationService,
    pub contract: EnigmaContract,
}

impl PrincipalManager{
    // load json config into the struct
    pub fn load_config(config_path : &str)-> Result<PrincipalConfig, Error> {
        let mut f = File::open(config_path)?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(serde_json::from_str(&contents)?)
    }
}

// General interface of a Sampler == The entity that manages the principal node logic.
pub trait Sampler {
    /// load with config from file 
    fn new(config : &str, emit : EmitParams, contract: EnigmaContract) -> Result<Self, Error> where Self: Sized;

    /// load with config passed from the caller (for mutation purposes)
    fn new_delegated(config_path : &str,emit : EmitParams, the_config : PrincipalConfig, contract: EnigmaContract) -> Self;

    fn get_contract_address(&self) -> Address;

    fn get_quote(&self) -> Result<String, Error>;

    fn get_report(&self,quote : &str) -> Result<(Vec<u8>, service::ASResponse), Error>;

    fn get_signing_address(&self) -> Result<String, Error>;

    fn get_account_address(&self) -> Address;

    fn get_network_url(&self) -> String;

    /// after initiation, this will run the principal node and block.
    fn run(&self)->Result<(),Error>;
}   

impl Sampler for PrincipalManager {
    fn new(config_path : &str, emit_params : EmitParams, contract: EnigmaContract) -> Result<Self, Error> {

        let config = PrincipalManager::load_config(config_path)?;
        let connection_str = config.attestation_service_url.clone();
        Ok(PrincipalManager{
            config_path : String::from(config_path),
            config,
            emit_params,
            as_service : service::AttestationService::new(&connection_str),
            contract,
        })
    }

    fn new_delegated(config_path : &str, emit_params : EmitParams, the_config : PrincipalConfig, contract: EnigmaContract) -> Self {
        let config = the_config;
        let connection_str = config.attestation_service_url.clone();
        PrincipalManager {
            config_path : String::from(config_path),
            config,
            emit_params,
            as_service : service::AttestationService::new(&connection_str),
            contract,
        }
    }

    fn get_contract_address(&self) -> Address { self.contract.address() }

    fn get_quote(&self) -> Result<String, Error> {
        let eid = self.emit_params.eid;
        Ok(retry_quote(eid, &self.config.spid, 8)?)
    }

    fn get_report(&self, quote : &str) -> Result<(Vec<u8>, service::ASResponse), Error> {
        let (rlp_encoded, as_response ) = self.as_service.rlp_encode_registration_params(quote)?;
        Ok((rlp_encoded,as_response))
    }

    fn get_signing_address(&self)-> Result<String, Error> {
        let eid = self.emit_params.eid;
        let mut signing_address = esgx::equote::get_register_signing_address(eid)?;
        // remove 0x
        signing_address = signing_address[2..].to_string();
        Ok(signing_address)
    }

    fn get_account_address(&self)-> Address { self.contract.account }

    fn get_network_url(&self) -> String {self.config.url.clone()}

    fn run(&self) -> Result<(), Error> {
        // get quote 
        let quote = self.get_quote()?;
        // get report 
        let (rlp_encoded, _ ) = self.get_report(&quote)?;
        // get enigma contract
        let enigma_contract = &self.contract;
        // register worker 
        //0xc44205c3aFf78e99049AfeAE4733a3481575CD26
        let signer = self.get_signing_address()?;
        println!("signing address = {}", signer);
        let gas = self.emit_params.gas_limit;
        enigma_contract.register(&signer, &rlp_encoded, gas)?;
        // watch blocks 
        let polling_interval = self.config.polling_interval.clone();
        let epoch_size = self.config.epoch_size.clone();
        let eid = self.emit_params.eid;
        let gas_limit = gas.clone();
        enigma_contract.watch_blocks(epoch_size, polling_interval, eid, gas_limit, self.emit_params.max_epochs);
        Ok(())
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]  
 mod test {
    use super::*;
    use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
    use enigma_tools_u::web3_utils::w3utils;
    use boot_network::deploy_scripts;
    use web3::types::{Log,H256};
    use esgx::general::init_enclave_wrapper;
    use std::env;
    use std::{thread, time};
    use std::sync::Arc;
    use enigma_tools_u::common_u::Keccak256;

    /// This function is important to enable testing both on the CI server and local. 
    /// On the CI Side: 
    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there. 
    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
    /// The default is set to ganache cli "http://localhost:8545"
    fn get_node_url()-> String {
        env::var("NODE_URL").unwrap_or(String::from("http://localhost:8545"))
    }

    /// Helper method to start 'miner' that simulates blocks. 
    pub fn run_miner(account: Address, w3: Arc<Web3<Http>>){
        let child = thread::spawn( move || {
            let url = get_node_url();
            deploy_scripts::forward_blocks(Arc::clone(&w3), 1,account, url);
        });
    }
    /// helps in assertion to check if a random event was indeed broadcast.
    pub fn filter_random(w3: Arc<Web3<Http>>, contract_addr : Option<&str>, url : &str , event_name : &str)-> Result<Vec<Log>, Error> {
        let logs = w3utils::filter_blocks(w3, contract_addr, event_name, url)?;
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
        let deploy_config = "../app/tests/principal_node/contracts/deploy_config.json";
        let mut config = deploy_scripts::load_config(deploy_config).unwrap();
        // modify to dynamic address
//        config.set_accounts_address(deployer);
        config.set_ethereum_url(get_node_url());

        let signer_addr = deploy_scripts::get_signing_address(eid).unwrap();
        // deploy all contracts. (Enigma & EnigmaToken)
        let enigma_contract = EnigmaContract::deploy_contract(
            &config.enigma_token_contract_path,
            &config.enigma_contract_path,
            &config.url,
            None,
            &signer_addr
        ).expect("cannot deploy Enigma,EnigmaToken");

        let account = enigma_contract.account.clone();

        // run simulated miner
        run_miner(account, Arc::clone(&enigma_contract.web3));

        // build the config
        let mut params : EmitParams = EmitParams {
            eid,
            gas_limit : 5999999,
            max_epochs : Some(5), 
            ..Default::default()
        };
        
        let principal_config = "../app/tests/principal_node/contracts/principal_test_config.json";
        let mut the_config = PrincipalManager::load_config(principal_config).unwrap();
        the_config.set_accounts_address(account.hex());
        the_config.set_enigma_contract_address(enigma_contract.address().hex());
        the_config.set_ethereum_url(get_node_url());
        let url = the_config.url.clone();

        // run event filter in the background
        let event_name =  "WorkersParameterized(uint256,address[],bool)";
        let w3 = Arc::clone(&enigma_contract.web3);
        let child = thread::spawn(move || {
            
            let mut counter = 0;
            loop{   
                counter +=1;
                let logs = filter_random(Arc::clone(&w3), None, &url, &event_name).expect("err filtering random");
                // the test: if events recieved >2 (more than 2 emitts of random)
                // assert topic (keccack(event_name))
                if logs.len() > 2 {
                    println!("FOUND 2 LOGS!!!! {:?}", logs);
                    for (idx, log) in logs.iter().enumerate(){
                        let expected_topic = event_name.as_bytes().keccak256();
                        assert!(log.topics[0].contains(&H256::from_slice(&expected_topic)));
                    }
                    break;
                }
                thread::sleep(time::Duration::from_secs(1));
                let max_time = 30;
                if counter > max_time {
                    panic!("test failed, more than {} seconds without events" ,max_time)
                }
            }
        });

        // run principal 
        let principal = PrincipalManager::new_delegated(principal_config, params, the_config, enigma_contract);
        principal.run().unwrap();
    }

 }
