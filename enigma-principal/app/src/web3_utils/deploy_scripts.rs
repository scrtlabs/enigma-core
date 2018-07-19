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
// FITLERS ADDITIONS ATTEMPTS 
use web3::api;
use tokio_core;

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
    println!("deployed dummy contract at address = {:?}",contract.address() );
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

////////////////////////////////////////////
/// ////////////////////////////////////////////
/// ////////////////////////////////////////////
/// ////////////////////////////////////////////
/// ////////////////////////////////////////////
/// ////////////////////////////////////////////
/// ////////////////////////////////////////////
/// 
pub fn test_block_listener(){

    
    const MAX_PARALLEL_REQUESTS: usize = 64;

    // deploy the dummy miner 
    let deployer = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");

    let url = "http://localhost:9545";
    
    let mut eloop = tokio_core::reactor::Core::new().unwrap();
    println!("shit ????000000 " );
    
    // let w3 = web3::Web3::new(
    //     web3::transports::Http::with_event_loop(
    //         url,
    //         &eloop.handle(),
    //         MAX_PARALLEL_REQUESTS,
    //     ).unwrap(),
    // );

    //let mut eloop = tokio_core::reactor::Core::new().unwrap();
    let (_eloop,w3) = w3utils::connect(&url).expect("cannot connect to ethereum network (miner)");

    let contract = deploy_dummy_miner(&w3, &deployer)
        .expect("cannot deploy dummy miner");

    let w3 = web3::Web3::new(web3::transports::WebSocket::with_event_loop(url, &eloop.handle()).unwrap());
    // // build event listener 
    println!("shit ????11111 " );
    let filter = FilterBuilder::default()
    .address(vec![contract.address()])
    .topics
    (
        Some(vec![
            "0x4229d50c63dbdc5551dd68e0a9879b01ac250cb31feaeba7588533462e6c7aaa".into(),
        ]),
        None,
        None,
        None,
    )
    .build();

    // start listening 
    println!("shit ???? " );
   let f =  w3.eth_subscribe()
    .subscribe_logs(filter)
    .then(|sub| {
        sub.unwrap().for_each(|log| {
            println!("got log: {:?}", log);
            Ok(())
        })
    })
    .map_err(|_| ());
    println!("after decl " );
    eloop.run(f).unwrap();
    println!("running shitza " );
    thread::sleep(time::Duration::from_secs(3));
    println!("done sleeping..." );

    let deployer : Address = deployer
            .parse()
            .expect("unable to parse deployer address");

    // emit event 
    contract.call("mine", (), deployer, Options::default()).wait().unwrap();

}



pub fn log_sub(){
    use web3;
    use web3::api;
    use web3::Web3;
    use std::time;
    use rustc_hex::FromHex;
    use web3::contract::{Contract, Options};
    use web3::futures::{Future, Stream};
    use web3::types::FilterBuilder;
    use tokio_core;
    let mut eloop = tokio_core::reactor::Core::new().unwrap();

    let web3 = web3::Web3::new(web3::transports::WebSocket::with_event_loop("ws://localhost:9545", &eloop.handle()).unwrap());

    // Get the contract bytecode for instance from Solidity compiler
    let (abi,bytecode) = w3utils::load_contract_abi_bytecode( "../app/tests/principal_node/contracts/Dummy.json").unwrap();
    let bytecode : Vec<u8> = w3utils::trunace_bytecode(&bytecode).expect("error parsing bytecode to bytes");

    eloop
        .run(web3.eth().accounts().then(|accounts| {
            let accounts = accounts.unwrap();
            println!("accounts: {:?}", &accounts);

            Contract::deploy(web3.eth(), abi.as_bytes())
                .unwrap()
                .confirmations(0)
                .poll_interval(time::Duration::from_secs(1))
                .options(Options::with(|opt| {
                    opt.gas = Some(3_000_000.into())
                }))
                .execute(bytecode, (), accounts[0])
                .unwrap()
                .then(move |contract| {
                    let contract = contract.unwrap();
                    println!("contract deployed at: {}", contract.address());

                    // Filter for Hello event in our contract
                    //0x4229d50c63dbdc5551dd68e0a9879b01ac250cb31feaeba7588533462e6c7aaa
                    let filter = FilterBuilder::default()
                        .address(vec![contract.address()])
                        .topics(
                            Some(vec![
                                "0xd282f389399565f3671145f5916e51652b60eee8e5c759293a2f5771b8ddfd2e".into(),
                            ]),
                            None,
                            None,
                            None,
                        )
                        .build();

                    let event_future = web3.eth_subscribe()
                        .subscribe_logs(filter)
                        .then(|sub| {
                            sub.unwrap().for_each(|log| {
                                println!("got log: {:?}", log);
                                Ok(())
                            })
                        })
                        .map_err(|_| ());

                    let call_future = contract
                        .call("mine", (), accounts[0], Options::default())
                        .then(|tx| {
                            println!("got tx: {:?}", tx);
                            Ok(())
                        });

                    event_future.join(call_future)
                })
        }))
        .unwrap();
}


use std::io::{self, Read};


pub fn read_input() {

    use web3;
    use web3::api;
    use web3::Web3;
    use std::time;
    use rustc_hex::FromHex;
    use web3::contract::{Contract, Options};
    use web3::futures::{Future, Stream};
    use web3::types::FilterBuilder;
    use tokio_core;

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(n) => {
            let mut eloop = tokio_core::reactor::Core::new().unwrap();
            println!("{}", input);
            let deployer : Address = input
            .parse()
            .expect("unable to parse deployer address");
            // listen to eventos 
            let w3 = web3::Web3::new(web3::transports::WebSocket::with_event_loop("ws://localhost:9545", &eloop.handle()).unwrap());
                // // build event listener 
                println!("shit ????11111 " );
                let filter = FilterBuilder::default()
                .address(vec![deployer])
                .topics
                (
                    Some(vec![
                        "0x4229d50c63dbdc5551dd68e0a9879b01ac250cb31feaeba7588533462e6c7aaa".into(),
                    ]),
                    None,
                    None,
                    None,
                )
                .build();

                // start listening 
                println!("shit ???? " );
            let f =  w3.eth_subscribe()
                .subscribe_logs(filter)
                .then(|sub| {
                    sub.unwrap().for_each(|log| {
                        println!("got log: {:?}", log);
                        Ok(())
                    })
                }) 
                .map_err(|_| ());
                println!("after decl " );
                //eloop.run(f).unwrap();
                eloop.remote().spawn(|_| f);
                println!("after decl2222222222222222222 " );

        }
        Err(error) => println!("error: {}", error),
    };
}

pub fn build_filter(contract_addr : String )->web3::types::Filter{
    
    let contract_addr : Address = contract_addr
                .parse()
                .expect("unable to parse contract_addr address");
    
    FilterBuilder::default()
    .address(vec![contract_addr])
    .build()
}
pub fn filter_blocks(contract_addr : String ){

    

    let url = "http://localhost:9545";
    let (eloop,w3) = w3utils::connect(&url).expect("cannot connect to ethereum");
    

    let filter = build_filter(contract_addr);

    //     let mut eloop = tokio_core::reactor::Core::new().unwrap();
    //  let w3 = web3::Web3::new(web3::transports::WebSocket::with_event_loop("ws://localhost:9545", &eloop.handle()).unwrap());
    match w3.eth().logs(filter).wait(){
        Ok(v)=>{println!("{:?}",v );},
        Err(e)=>{println!("{:?}",e );},
    };
}

pub fn filter_blocks_by_addr(){
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(n) => {
            println!("{} bytes read", n);
            println!("{}", input);
            filter_blocks(input.clone());
        }
        Err(error) => println!("error: {}", error),
    }
}