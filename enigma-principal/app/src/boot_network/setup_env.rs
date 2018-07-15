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
    fn new(config : &str, emit : EmittParams)->Self;
    fn get_quote(&self)->Result<String,Error>;
    fn get_report(&self,quote : &String)->Result<(Vec<u8>,service::ASResponse),Error>;
    fn connect(&self)->Result<(web3::transports::EventLoopHandle, Web3<Http>),Error>;
    fn enigma_contract(&self,web3::transports::EventLoopHandle, Web3<Http>)->Result<EnigmaContract,Error>;
    fn get_signing_address(&self)->Result<String,Error>;
    fn run(&self)->Result<(),Error>;
}   

impl Sampler for PrincipalManager {
    fn new(config_path : &str,emit : EmittParams)-> Self{

        let config = PrincipalManager::load_config(config_path);
        let connection_str = config.ATTESTATION_SERVICE_URL.clone();
        PrincipalManager{
            config_path : config_path.to_string(),
            config : config,
            emitt_params : emit,
            as_service : service::AttestationService::new(&connection_str),
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
        let address = self.config.ENIGMA_CONTRACT_ADDRESS.clone();
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
        let signing_address = esgx::equote::get_register_signing_address(eid)?;
        Ok(signing_address)
    }
    fn run(&self)->Result<(),Error>{
        // get quote 
        let quote = self.get_quote()?;
        // get report 
        let (rlp_encoded, as_response ) = self.get_report(&quote)?;
        // get enigma contract 
        let (eloop, http) = self.connect()?;
        let enigma_contract = self.enigma_contract(eloop,http)?;
        // register worker 
         //0xc44205c3aFf78e99049AfeAE4733a3481575CD26
        let signer = self.get_signing_address()?;
        println!("signing address = {}", signer);
        // TODO:: implement deploying the enigma contract
        let signer = String::from("c44205c3aFf78e99049AfeAE4733a3481575CD26");
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


pub fn get_rlp_encoded_report()->Result<(Vec<u8>,service::ASResponse),Error>{
    let service : service::AttestationService = service::AttestationService::new(constants::ATTESTATION_SERVICE_URL);
    let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
    let (rlp_encoded, as_response ) = service.rlp_encode_registration_params(&quote).unwrap();
    Ok((rlp_encoded,as_response))
}


fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545")
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
}


pub fn enigma_contract_builder()->enigma_contract::EnigmaContract{
    let (eloop, web3) = setup();
    // deployed contract address
    let address = "345cA3e014Aaf5dcA488057592ee47305D9B3e10";
    // path to the build file of the contract 
    let path = "/root/enigma-core/enigma-principal/app/src/boot_network/enigma_full.abi";
    // the account owner that initializes 
    let account = "627306090abab3a6e1400e9345bc60c78a8bef57";
    let url = "http://localhost:9545";
    let enigma_contract : enigma_contract::EnigmaContract = Principal::new(web3,eloop, address, path, account,url);
    enigma_contract
}
// enigma contract 
pub fn run2(eid: sgx_enclave_id_t){
    let enigma_contract = enigma_contract_builder();
    // fetch report 
    let (encoded_report , as_response ) = get_rlp_encoded_report().unwrap();
    // register worker 
    // signer_addr = address representation of the public key generated in the report 
    
    let signer = String::from("c44205c3aFf78e99049AfeAE4733a3481575CD26");
    let gas_limit = String::from("5999999");
    enigma_contract.register_as_worker(&signer,&encoded_report,&gas_limit ).unwrap();
    // begin loop process
    let epoch_size = 2;
    let polling_interval = 1;
    enigma_contract.watch_blocks(epoch_size, polling_interval, eid, gas_limit);
}
pub fn run3(eid: sgx_enclave_id_t){
    let (eloop, web3) = setup();
    let password = "c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
    
    let contract_address: Address = "627306090abab3a6e1400e9345bc60c78a8bef57"
            .parse()
            .expect("unable to parse contract address");

    let success = web3.personal().unlock_account(contract_address, password, None).wait().unwrap();
    println!("unlocked account ? {}", success);
}

pub fn run_REAL_REAL(eid: sgx_enclave_id_t){
    
    let mut params : EmittParams = EmittParams{ eid : eid, 
        gas_limit : String::from("5999999"), 
        ..Default::default()};

    let principal = PrincipalManager::new("../app/src/boot_network/config.json",params);
    principal.run().unwrap();
}

pub fn get_fake_ctor()->(Address,Address)
{
    let account = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");
    let account: Address = account
            .parse()
            .expect("unable to parse account address");
    (account,account)
}
pub fn run(eid: sgx_enclave_id_t){
    let abi = EnigmaContract::load_abi("../app/src/boot_network/enigma_full.abi").unwrap();
    let bytecode = EnigmaContract::load_bytecode("../app/src/boot_network/enigma_full.abi").unwrap();

    let uri = "http://localhost:9545";
    let deployer = "627306090abab3a6e1400e9345bc60c78a8bef57";
    let gas_limit = "5999999";
    let tx : w3utils::DeployParams = w3utils::DeployParams::new(deployer.to_string(),abi,bytecode,gas_limit.to_string());

    let (eloop,w3) = w3utils::connect(uri).unwrap();
    w3utils::deploy_contract(&w3, tx,get_fake_ctor()).unwrap();
    println!("finished turn OFF ------------------------------------------------" );
}