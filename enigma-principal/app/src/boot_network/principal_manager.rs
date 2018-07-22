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
use boot_network::enigma_contract;
use boot_network::enigma_contract::EnigmaContract;
use boot_network::principal_utils::Principal;
use boot_network::principal_utils::{EmittParams};
// files 
use std::fs::File;
use std::io::prelude::*;
use serde_derive::*;
use serde_json;
use serde_json::{Value};
// TESTING FOR W3UTILS
use web3_utils::w3utils;
use web3_utils::deploy_scripts;

#[derive(Serialize, Deserialize, Debug)]
pub struct PrincipalConfig {

    pub ENIGMA_CONTRACT_PATH : String,
    pub ENIGMA_CONTRACT_REMOTE_PATH : String,
    pub ENIGMA_CONTRACT_ADDRESS : String,
    pub ACCOUNT_ADDRESS : String,
    pub TEST_NET : bool,
    pub WITH_PRIVATE_KEY : bool,
    pub PRIVATE_KEY : String,
    pub URL : String,
    pub EPOCH_SIZE : usize,
    pub POLLING_INTERVAL : u64,
    pub SPID : String,
    pub ATTESTATION_SERVICE_URL : String,

}

pub struct PrincipalManager {
    custom_contract_address : Option<Address>,
    config_path : String,
    pub config : PrincipalConfig,
    emitt_params : EmittParams,
    as_service : service::AttestationService,
}

impl PrincipalManager{
    pub fn load_config(config_path : &str)-> PrincipalConfig {
       
        let mut f = File::open(config_path)
        .expect("file not found.");

       let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("canno't read file");

       serde_json::from_str(&contents).unwrap()
    }
}


trait Sampler {
    fn new(config : &str, emit : EmittParams, custom_contract_address : Option<Address>)->Self;
    fn get_contract_address(&self)->String;
    fn get_quote(&self)->Result<String,Error>;
    fn get_report(&self,quote : &String)->Result<(Vec<u8>,service::ASResponse),Error>;
    fn connect(&self)->Result<(web3::transports::EventLoopHandle, Web3<Http>),Error>;
    fn enigma_contract(&self,web3::transports::EventLoopHandle, Web3<Http>)->Result<EnigmaContract,Error>;
    fn get_signing_address(&self)->Result<String,Error>;
    fn run(&self)->Result<(),Error>;
}   

impl Sampler for PrincipalManager {
    fn new(config_path : &str,emit : EmittParams, custom_contract_address : Option<Address>)-> Self{

        let config = PrincipalManager::load_config(config_path);
        let connection_str = config.ATTESTATION_SERVICE_URL.clone();
        PrincipalManager{
            custom_contract_address : custom_contract_address,
            config_path : config_path.to_string(),
            config : config,
            emitt_params : emit,
            as_service : service::AttestationService::new(&connection_str),
        }
    }
    fn get_contract_address(&self)->String{

        match self.custom_contract_address.unwrap(){

            a => w3utils::address_to_string_addr(&a),
            _ => self.config.ENIGMA_CONTRACT_ADDRESS.clone(),
        }

    }
    fn get_quote(&self)->Result<String,Error>{
        let eid = self.emitt_params.eid;
         match esgx::equote::produce_quote(eid, &self.config.SPID){
             Ok(quote) =>{
                Ok(quote)
             },
             Err(e)=>{
                Err(e)
             }
         }
    }
    fn get_report(&self, quote : &String)->Result<(Vec<u8>,service::ASResponse),Error>{
        let (rlp_encoded, as_response ) = self.as_service.rlp_encode_registration_params(quote)?;
        Ok((rlp_encoded,as_response))
    }
    fn connect(&self)->Result<(web3::transports::EventLoopHandle, Web3<Http>),Error>{
        let (_eloop, http) = web3::transports::Http::new(&self.config.URL.clone())
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        Ok((_eloop, w3))
    }
    fn enigma_contract(&self,eloop : web3::transports::EventLoopHandle, web3 : Web3<Http>)->Result<EnigmaContract,Error>{
        // deployed contract address
        let address = self.get_contract_address();
        // path to the build file of the contract 
        let path = self.config.ENIGMA_CONTRACT_PATH.clone();
        // the account owner that initializes 
        let account = self.config.ACCOUNT_ADDRESS.clone();
        // the ethereum node url
        let url = self.config.URL.clone();
        let enigma_contract : EnigmaContract = Principal::new(web3,eloop, &address, &path, &account, &url);
        Ok(enigma_contract)
    }
    fn get_signing_address(&self)->Result<String,Error>{
        let eid = self.emitt_params.eid;
        let mut signing_address = esgx::equote::get_register_signing_address(eid)?;
        // remove 0x
        signing_address = signing_address[2..].to_string();
        Ok(signing_address)
    }
    fn run(&self)->Result<(),Error>{
        // get quote 
        let quote = self.get_quote()?;
        // get report 
        let (rlp_encoded, as_response ) = self.get_report(&quote)?;
        // get enigma contract 
        let (eloop, w3) = self.connect()?;
        let enigma_contract = self.enigma_contract(eloop,w3)?;
        // register worker 
        //0xc44205c3aFf78e99049AfeAE4733a3481575CD26
        let signer = self.get_signing_address()?;
        println!("signing address = {}", signer);
        let gas_limit = &self.emitt_params.gas_limit;
        enigma_contract.register_as_worker(&signer,&rlp_encoded,&gas_limit)?;
        // watch blocks 
        let polling_interval = self.config.POLLING_INTERVAL;
        let epoch_size = self.config.EPOCH_SIZE;
        let eid = self.emitt_params.eid;
        let gas_limit = gas_limit.clone();
        enigma_contract.watch_blocks(epoch_size, polling_interval, eid, gas_limit);
        Ok(())
    }
}

pub fn run_miner(){
    let child = thread::spawn(move || {
        let url = "http://localhost:9545";
        let deployer = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");
        deploy_scripts::forward_blocks(1,deployer, url.to_string());
    });
}
pub fn run_real(eid: sgx_enclave_id_t){

    // deploy contracts 
    
    let deploy_config = "../app/tests/principal_node/contracts/deploy_config.json";
    let (enigma_contract, enigma_token ) = deploy_scripts::deploy_base_contracts
    (
        eid, 
        deploy_config, 
        None
    )
    .expect("cannot deploy Enigma,EnigmaToken");
    
    // run block simulation 
    
    run_miner();
    
    thread::sleep(time::Duration::from_secs(3));
    
    // run principal 
    
    let mut params : EmittParams = EmittParams{ eid : eid, 
        gas_limit : String::from("5999999"), 
        ..Default::default()};

    let principal = PrincipalManager::new("../app/src/boot_network/config.json",params, Some(enigma_contract.address()));
    principal.run().unwrap();
}

pub fn run(eid: sgx_enclave_id_t){
    let contract_addr = String::from("8cdaf0cd259887258bc13a92c0a6da92698644c0");
    let url = String::from("http://localhost:9545");
    let event_name = String::from("Hello(address)");
    let logs = w3utils::filter_blocks(Some(contract_addr),event_name, url).unwrap();
    println!("{:?}",logs);

}

//////////////////////// TESTS  /////////////////////////////////////////

//  #[cfg(test)]  
//  mod test {
 
//     fn connect()->(web3::transports::EventLoopHandle, Web3<Http>,Vec<Address>){
//         let uri = "http://localhost:8545";
//         let (eloop,w3) = w3utils::connect(uri).unwrap();
//         let accounts = w3.eth().accounts().wait().unwrap();
//         (eloop,w3, accounts)
//     }

//     #[test]
//     #[ignore]
//     fn test_deploy_enigma_contract_environment(){
//         // init enclave 
//         let enclave = match init_enclave() {
//             Ok(r) => {
//                 println!("[+] Init Enclave Successful {}!", r.geteid());
//                 r
//             },
//             Err(x) => {
//                 println!("[-] Init Enclave Failed {}!", x.as_str());
//                 assert_eq!(0,1);
//                 return;
//             },
//         };
//         let (eloop,w3,accounts) = connect();
//         // 
//         let deploy_config = "../app/tests/principal_node/contracts/deploy_config.json";
//         let (enigma_contract, enigma_token ) = deploy_scripts::deploy_base_contracts
//         (
//             eid, 
//             deploy_config, 
//             None
//         )
//         .expect("cannot deploy Enigma,EnigmaToken");
//         }
//  }