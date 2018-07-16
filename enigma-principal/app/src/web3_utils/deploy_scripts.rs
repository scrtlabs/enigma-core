// general 
// TODO: refactor into crate 
use web3_utils::w3utils;
use failure::Error;
use rustc_hex::FromHex;
use std::time;
use std::str;
use esgx;
use std::thread;
//web3
use web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use web3::types::FilterBuilder;
use web3::transports::Http;
use web3::Web3;
use web3::contract::tokens::Tokenize;
// files 
use std::fs::File;
use std::io::prelude::*;
use serde_derive::*;
use serde_json;
use serde_json::{Value};
// url 
use url::{Url};
// sgx 
use sgx_types::{sgx_enclave_id_t};

#[derive(Serialize, Deserialize, Debug)]
struct ScriptDeployConfig {
    pub ENIGMA_CONTRACT_PATH : String,
    pub ENIGMA_TOKEN_CONTRACT_PATH : String,
    pub ACCOUNT_ADDRESS : String,
    pub URL : String
}

fn load_config(config_path : &str)->ScriptDeployConfig{
           let mut f = File::open(config_path)
        .expect("file not found.");

       let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("canno't read file");

       serde_json::from_str(&contents).unwrap()
}
/// TESTING: this function deploys the Enigma and EnigmaToken contract 
pub fn deploy_base_contracts(eid : sgx_enclave_id_t, 
    config_path : &str,
    url : Option<Url>)->Result<(Contract<Http>,Contract<Http>),Error>{

    // load all config 
    let config : ScriptDeployConfig = load_config(config_path);
    let (e_abi,e_bytecode) = w3utils::load_contract_abi_bytecode(&config.ENIGMA_CONTRACT_PATH.as_str())
        .expect("canot load enigma contract.");
    let (et_abi,et_bytecode) = w3utils::load_contract_abi_bytecode(&config.ENIGMA_TOKEN_CONTRACT_PATH.as_str())
        .expect("cannot load enigma token contract.");
    // connect to ethereum 
    let url = match url {
        Some(u) => u.into_string(),
        None => config.URL,
    };
    let (eloop,w3) = w3utils::connect(&url.as_str()).expect("cannot connect to ethereum");
    // deploy the enigma token 

    let token_contract = deploy_enigma_token_contract
    (
        &w3, 
        config.ACCOUNT_ADDRESS.clone() , 
        et_abi, 
        et_bytecode
    )
    .expect("cannot deploy enigma token.");    

    // deploy the enigma contract
    let token_addr = token_contract.address();//.to_string();
    let signer_addr = get_signing_address(eid).expect("cannot get signer address from sgx");
    let enigma_contract = deploy_enigma_contract
    (
        &w3, 
        config.ACCOUNT_ADDRESS.clone(), 
        e_abi, 
        e_bytecode, 
        token_addr, 
        signer_addr
    )
    .expect("cannot deplot enigma contract");

    Ok((enigma_contract, token_contract))
}
/// TESTING: deploy the EnigmaToken contract
pub fn deploy_enigma_token_contract(w3 : &Web3<Http>, 
    deployer : String, 
    abi : String, 
    bytecode : String)->Result<Contract<Http>,Error>{

    let gas_limit = String::from("5999999");
    let confirmations = 0;
    let polling_interval = 1;
    let tx_params = w3utils::DeployParams::new
    (
        deployer, 
        abi, 
        bytecode, 
        gas_limit, 
        polling_interval, 
        confirmations
    );
    let contract = w3utils::deploy_contract(w3, tx_params, ())
        .expect("failed to deploy EnigmaToken contract");
    Ok(contract)
}

/// TESTING: deploy the Enigma contract
pub fn deploy_enigma_contract(w3 : &Web3<Http>, 
    deployer : String, 
    abi : String, 
    bytecode : String, 
    token_addr : Address, 
    signer_addr : String)->Result<Contract<Http>,Error>{

    // generate ctor params 
    let signer_addr: Address = signer_addr
        .parse().expect("unable to parse signer_addr address");
    let input = (token_addr,signer_addr);
    // tx params 
    let gas_limit = String::from("5999999");
    let confirmations = 0;
    let polling_interval = 1;
    let tx_params = w3utils::DeployParams::new
    (
        deployer, 
        abi, 
        bytecode, 
        gas_limit, 
        polling_interval, 
        confirmations
    );
    // deploy 
    let contract = w3utils::deploy_contract(w3, tx_params, input)
        .expect("failed to deploy Enigma contract");
    Ok(contract)
}

/// get the signer addr 
pub fn get_signing_address(eid : sgx_enclave_id_t)->Result<String,Error>{
        let eid = eid;
        let mut signing_address = esgx::equote::get_register_signing_address(eid)?;
        signing_address = signing_address[2..].to_string();
        Ok(signing_address)
}

/// TESTING: deploy the dummy contract 
fn deploy_dummy_miner(w3 : &Web3<Http>, deployer : &String)->Result<Contract<Http>,Error>{
    // contract path 
    let path = "../app/tests/principal_node/contracts/Dummy.json";
    // build deploy params 
    let deployer = deployer.clone();
    let gas_limit = "5999999";
    let poll_interval : u64 = 1;
    let confirmations : usize = 0;
    let (abi,bytecode) = w3utils::load_contract_abi_bytecode(path)?;

    let tx = w3utils::DeployParams::new(
            deployer,
            abi,bytecode,
            gas_limit.to_string(),
            poll_interval,
            confirmations);
    // deploy
    let contract = w3utils::deploy_contract(&w3, tx,()).unwrap();
    Ok(contract)
}

/// TESTING: mimic block creation to test the watch blocks method of the principal node 
pub fn forward_blocks(interval : u64, deployer : String, url : String){
    let (eloop,w3) = w3utils::connect(&url.as_str()).expect("cannot connect to ethereum network (miner)");
    let contract = deploy_dummy_miner(&w3, &deployer).expect("cannot deploy dummy miner");
    
    let deployer : Address = deployer
            .parse()
            .expect("unable to parse deployer address");
    loop {
        let gas_limit = String::from("5999999");
        let mut options = Options::default();
        let mut gas : U256 = U256::from_dec_str(&gas_limit).unwrap();
        options.gas = Some(gas);
        contract.call("mine",(),deployer,options ).wait().unwrap();
        println!("new block mined..." );
        thread::sleep(time::Duration::from_secs(interval));
    }
}


