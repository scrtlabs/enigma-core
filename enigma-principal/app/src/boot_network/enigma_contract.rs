//sgx 
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
// general 
use rlp;
use enigma_tools_u;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::attestation_service::constants;
use failure::Error;
//web3
use web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use rustc_hex::FromHex;
use web3::transports::Http;
use web3::Web3;
// files 
use std::fs::File;
use std::io::prelude::*;
use serde_json;
use serde_json::{Value};
// general 
use web3_utils::w3utils;

pub struct EnigmaContract{

    pub web3 : Web3<Http>,
    pub contract : Contract<Http>, 
    pub account : Address,
    pub eloop : web3::transports::EventLoopHandle,
    pub abi_path : String,
    pub address_str : String,
    pub account_str : String,
    pub url : String,
    pub abi_str : String,
}


impl EnigmaContract{
    pub fn new(web3: Web3<Http>, eloop : web3::transports::EventLoopHandle ,address: &str, path: &str, account: &str, url : &str) -> Self{

        let account_str = account.to_string();
        let address_str =  address.to_string();
    
        let contract_address: Address = address
            .parse()
            .expect("unable to parse contract address");

        let (contract, abi_str) = EnigmaContract::deployed(&web3, contract_address, path);

        let account: Address = account
            .parse()
            .expect("unable to parse account address");
                    
        EnigmaContract {
            web3: web3, 
            contract: contract, 
            account : account , 
            eloop : eloop , 
            abi_path : path.to_string(), 
            address_str :address_str, 
            account_str : account_str,
            url : url.to_string(),
            abi_str : abi_str,
        }
     }
        /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider
    pub fn deployed(web3: &Web3<Http>, address: Address, path: &str) -> (Contract<Http>, String) {
       let (abi,_bytecode) = EnigmaContract::load_abi(path).unwrap();
       let abi_str = abi.clone();
       let contract = Contract::from_json(
           web3.eth(), 
           address, 
           abi.as_bytes(),
         ).expect("unable to fetch the deployed contract on the Ethereum provider");

        (contract,abi_str)
    }
    /// connect to web3 and Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider
    pub fn connect_to_deployed(url : String, address: Address , abi : String) -> Result<Contract<Http>,Error> {
       let (_eloop, w3) = EnigmaContract::connect(url.as_str());
       let contract = Contract::from_json(
           w3.eth(), 
           address, 
           abi.as_bytes(),
         ).expect("unable to fetch the deployed contract on the Ethereum provider");
        Ok(contract)
    }
    // given a path load EnigmaContract.json and extract the ABI
    pub fn load_abi(path: &str) -> Result<(String,String),Error>{
        let (abi,bytecode) = w3utils::load_contract_abi_bytecode(path)?;
        Ok((abi,bytecode))
    }
    pub fn load_bytecode(path: &str) -> Result<String,Error>{
       let (_abi,bytecode) = w3utils::load_contract_abi_bytecode(path)?;
    
        Ok(bytecode)
    }

    pub fn register_as_worker(&self, signer : &String, report : &Vec<u8>, gas_limit: &String)->Result<(),Error>{
        // register 
        let signer_addr : Address = signer.parse().unwrap();
        let mut options = Options::default();
        let mut gas : U256 = U256::from_dec_str(gas_limit).unwrap();
        options.gas = Some(gas);
        println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2" );
    println!("@@@@@@@@@@@@@@@@           registering with  signer addr =     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2" );
    println!("{}",signer );
    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2" );
    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2" );
        // call the register function
        self.contract.call("register",(signer_addr,report.to_vec(),),self.account,options ).wait().expect("error registering to the enigma smart contract.");
        Ok(())
    }
    pub fn connect(url : &str) -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new(url)
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
    }
}

        