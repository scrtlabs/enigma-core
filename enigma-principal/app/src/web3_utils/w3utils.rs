// general 
use failure::Error;
use rustc_hex::FromHex;
use std::time;
use std::str;
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
// TO DELETE AFTER REFACTOR 
use boot_network::enigma_contract::EnigmaContract;

pub struct DeployParams{
    pub deployer : Address,
    pub abi : String, 
    pub gas_limit : U256,
    pub bytecode : String,
}

impl DeployParams{
    pub fn new(deployer : String, abi : String,bytecode: String, gas_limit : String)-> Self{
        
        let gas : U256 = U256::from_dec_str(&gas_limit).unwrap();
        
        let deployer_addr: Address = deployer
            .parse()
            .expect("unable to parse contract address");
        
        DeployParams{
            deployer : deployer_addr,
            abi : abi,
            gas_limit : gas,
            bytecode : bytecode,
        }
    }
}
// connect to ethereum 
pub fn connect( url : &str)->Result<(web3::transports::EventLoopHandle, Web3<Http>),Error>{
        let (_eloop, http) = web3::transports::Http::new(url)
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        Ok((_eloop, w3))
}


// private:: truncate the bytecode from solidity json 
// this method does 2 things:
// 1) web3 requires byte array of the hex byte code from_hex 
// 2) serde_json reads the bytecode as string with "0x..." so 4 chars needs to be removed.
// TODO:: solve the fact that serde dont ignore `"`
fn trunace_bytecode(bytecode : &String)->Result<Vec<u8>,Error>{
    //println!("str len = {}",bytecode );
    let mut b = bytecode.as_bytes();
    let sliced = &b[3..b.len()-1];
    println!("slice len = {}",sliced.len() );
    //sliced.to_vec().from_hex().unwrap()
    let result = str::from_utf8(&sliced.to_vec()).unwrap().from_hex()?;
    Ok(result)
}
// deploy any smart contract 
pub fn deploy_contract<P>(web3 : &Web3<Http>, tx_params : DeployParams  ,ctor_params : P)-> Result<Contract<Http>,Error>
where 
P : Tokenize
{    
    let bytecode : Vec<u8> = trunace_bytecode(&tx_params.bytecode).expect("error parsing bytecode to bytes");

    let deployer_addr = tx_params.deployer;
    let mut options = Options::default();
        options.gas = Some(tx_params.gas_limit);

    let builder = Contract::deploy(
            web3.eth(),
            tx_params.abi.as_bytes(),
        ).unwrap()
        .confirmations(0)
        .poll_interval(time::Duration::from_secs(1));
        
    let contract = builder
        .options(options)
        .execute(
            bytecode,
            ctor_params,
            deployer_addr,     
        )
        .expect("Cannot deploy contract abi")
        .wait()
        .unwrap();

        println!("deployed contract at address = {}",contract.address());

        Ok(contract)
}

// deploy the enigma smart contract 




 #[cfg(test)]  
 mod test {
    use web3_utils;
    use web3_utils::w3utils;
    use super::*;

     #[test]
     #[ignore]
     fn test_deploy_enigma_contract(){ 
        // 1) generate ctor input 
        // the enigma contract requires 2 addresses in the constructor 
        let account = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");
        let fake_input: Address = account.parse().expect("unable to parse account address");
        let fake_input = (fake_input,fake_input);
        // 2) load the abi and the bytecode 
        let abi = EnigmaContract::load_abi("../app/src/boot_network/enigma_full.abi").unwrap();
        let bytecode = EnigmaContract::load_bytecode("../app/src/boot_network/enigma_full.abi").unwrap();
        // 3) configurations 
        let uri = "http://localhost:9545";
        let deployer = "627306090abab3a6e1400e9345bc60c78a8bef57";
        let gas_limit = "5999999";
        let tx : w3utils::DeployParams = w3utils::DeployParams::new(deployer.to_string(),abi,bytecode,gas_limit.to_string());
        // 4) deploymend 
        let (eloop,w3) = w3utils::connect(uri).unwrap();
        w3utils::deploy_contract(&w3, tx,fake_input).unwrap();
     }
 }