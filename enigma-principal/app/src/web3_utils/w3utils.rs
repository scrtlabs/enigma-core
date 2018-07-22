// general 
use failure::Error;
use rustc_hex::FromHex;
use std::time;
use std::thread;
use std::str;
use tiny_keccak::Keccak;
//web3
use web3;
use web3::types::BlockNumber;
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

// hash traits, same as ethereum's hash function
pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}
impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}


pub struct DeployParams{
    pub deployer : Address,
    pub abi : String, 
    pub gas_limit : U256,
    pub bytecode : String,
    pub poll_interval : u64,
    pub confirmations : usize,

}

impl DeployParams{
    pub fn new(deployer : String, abi : String,bytecode: String, gas_limit : String, poll_interval : u64, confirmations : usize)-> Self{
        
        let gas : U256 = U256::from_dec_str(&gas_limit).unwrap();
        
        let deployer_addr: Address = deployer
            .parse()
            .expect("unable to parse contract address");
        
        DeployParams{
            deployer : deployer_addr,
            abi : abi,
            gas_limit : gas,
            bytecode : bytecode,
            poll_interval : poll_interval,
            confirmations : confirmations
        }
    }
}

// given a path load EnigmaContract.json and extract the ABI and the bytecode
pub fn load_contract_abi_bytecode(path: &str) -> Result<(String,String),Error>{

    let mut f = File::open(path)
    .expect("file not found."); 

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("canno't read file");
    
    let contract_data : Value = serde_json::from_str(&contents)
        .expect("unable to parse JSON built contract");

    let abi = serde_json::to_string(&contract_data["abi"])
        .expect("unable to find the abi key at the root of the JSON built contract");

    let bytecode = serde_json::to_string(&contract_data["bytecode"])
    .expect("unable to find the abi key at the root of the JSON built contract");

    Ok((abi,bytecode))
}
// connect to ethereum 
pub fn connect( url : &str)->Result<(web3::transports::EventLoopHandle, Web3<Http>),Error>{
        let (_eloop, http) = web3::transports::Http::new(url)
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        Ok((_eloop, w3))
}

// connect to an existing deployed smart contract 

pub fn deployed_contract(web3: &Web3<Http>, contract_addr: Address , abi : &String)->Result<Contract<Http>,Error>{
       

       let abi_str = abi.clone();
       
       let contract = Contract::from_json(
           web3.eth(), 
           contract_addr, 
           abi_str.as_bytes(),
         ).expect("unable to fetch the deployed contract on the Ethereum provider");

        Ok(contract)
}
// private:: truncate the bytecode from solidity json 
// this method does 2 things:
// 1) web3 requires byte array of the hex byte code from_hex 
// 2) serde_json reads the bytecode as string with '"0x..."' so 4 chars needs to be removed.
// TODO:: solve the fact that serde dont ignore `"`
pub fn trunace_bytecode(bytecode : &String)->Result<Vec<u8>,Error>{
    let mut b = bytecode.as_bytes();
    let sliced = &b[3..b.len()-1];
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
        .confirmations(tx_params.confirmations)
        .poll_interval(time::Duration::from_secs(tx_params.poll_interval));
        
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

//////////////////////// EVENTS LISTENING START ///////////////////////////

fn build_event_fuilder(event_name : String,contract_addr : Option<String>)->web3::types::Filter{
    let with_addr = contract_addr.is_some();
    let filter = FilterBuilder::default()
        .topics(Some(vec![
                event_name.as_bytes().keccak256().into(),
            ]),
                None,
                None,
                None,
        )
        .from_block(BlockNumber::Earliest)
        .to_block(BlockNumber::Latest);
    filter.address(vec![contract_addr.unwrap().parse().unwrap()]).build()
}
fn build_event_fuilder2(event_name : String,contract_addr : Option<String>)->web3::types::Filter{
    FilterBuilder::default().build()
    // let event = "Hello(address)".as_bytes();
    // //works "0x42487d8c593e0a9ff01966e22f9924ccd42728eb5c4592575f2dc4a3fe45f953"
    // let mut builder = FilterBuilder::default()
    //     .topics(Some(vec![
    //             event_name.as_bytes().keccak256().into(),
    //         ]),
    //             None,
    //             None,
    //             None,
    //     )
    //     .from_block(BlockNumber::Earliest)
    //     .to_block(BlockNumber::Latest);
    //     builder.build()
    // if contract_addr.is_some(){
    //     let contract_addr : Address = contract_addr
    //     .unwrap()
    //     .parse()
    //     .expect("unable to parse contract_addr address");    

    //     &builder.address(vec![contract_addr]);
    // }
}
/// TESTING: filter the network for events 
pub fn filter_blocks2(contract_addr : String ,url : String){

    // let (eloop,w3) = connect(&url.as_str())
    //     .expect("cannot connect to ethereum");

    // let contract_addr = contract_addr.clone();

    // let filter = build_event_fuilder(contract_addr.clone());
    // let res = w3.eth().logs(filter).wait();
    // match res {
    //     Ok(logs)=>println!("all good im happy and works {:?} ",logs),
    //     Err(e) => println!("[-] Event filter error {}",e),
    // };

}
pub fn filter_blocks(contract_addr : String ,url : String){
    let (eloop,w3) = connect(&url.as_str())
        .expect("cannot connect to ethereum");

    let contract_addr = contract_addr.clone();
    //"Hello(address)"
    let filter = build_event_fuilder(String::from("Hello(address)"),Some(contract_addr.clone()));

    let future = w3.eth()
            .logs(filter)
            .then(move |res|{
                match res {
                    Ok(logs)=>{
                        println!("Ok git shit  {:?}", logs );
                    },
                    Err(e) =>{
                        println!("Err git shit {:?} ",e );
                    },
                }

            Ok(())
        });
        eloop.remote().spawn(|_| future);
        loop{
          thread::sleep(time::Duration::from_secs(1));  
        }
}

//////////////////////// EVENTS LISTENING END ///////////////////////////
/// 
/// turn an Address to a string address and remove the 0x
pub fn address_to_string_addr(addr : &Address)->String{
    let mut addr  = format!("{:?}", addr);
    addr = addr[2..].to_string();
    addr

}
 #[cfg(test)]  
 mod test {
    use web3_utils;
    use web3_utils::w3utils;
    use std::collections::HashMap;
    use super::*;
    
    // helper: given a contract name return the bytecode and the abi 
    fn get_contract(ctype : &String)->(String,String){
        let EnigmaToken = "../app/tests/principal_node/contracts/EnigmaToken.json";
        let Enigma = "../app/tests/principal_node/contracts/Enigma.json";
        let Dummy =  "../app/tests/principal_node/contracts/Dummy.json";

        let to_load = match ctype.as_ref() {
            "EnigmaToken" => {
                EnigmaToken
            },
            "Enigma"=> {
                Enigma
            },
            "Dummy"=> {
                Dummy
            },
            _ => {
                ""
            }
        };
        assert_ne!(to_load,"" , "wrong contract type");

        let (abi,bytecode) = w3utils::load_contract_abi_bytecode(to_load).unwrap();
        (abi,bytecode)
    }
    // helper to quickly mock params for deployment of a contract to generate DeployParams 
    fn get_deploy_params(ctype : &str)->w3utils::DeployParams{
        
        let deployer = "627306090abab3a6e1400e9345bc60c78a8bef57";
        let gas_limit = "5999999";
        let poll_interval : u64 = 1;
        let confirmations : usize = 0;
        let (abi,bytecode) = get_contract(&ctype.to_string());

        w3utils::DeployParams::new(
            deployer.to_string(),
            abi,bytecode,
            gas_limit.to_string(),
            poll_interval,
            confirmations)
    }
    // helper connect to web3 
    fn connect()->(web3::transports::EventLoopHandle, Web3<Http>){
        let uri = "http://localhost:9545";
        let (eloop,w3) = w3utils::connect(uri).unwrap();
        (eloop,w3)
    }
    // helper deploy a dummy contract and return the contract instance
    fn deploy_dummy(w3 : &Web3<Http>)->Contract<Http>{
        let tx = get_deploy_params("Dummy");
        let contract = w3utils::deploy_contract(&w3, tx,()).unwrap();
        contract
    }
    #[test] 
    //#[ignore]
    fn test_deploy_dummy_contract(){
        let (eloop,w3) = connect();
        let contract = deploy_dummy(&w3);
        // validate deployment 
        // mine func add to a uint256=0 1 and returns it's value 
        let result = contract.query("mine", (), None, Options::default(), None);
        let param : U256 = result.wait().unwrap();
        assert_eq!(param.as_u64(), 1);

    }
     #[test]
     //#[ignore]
     fn test_deploy_enigma_contract(){ 
        // 1) generate ctor input 
        // the enigma contract requires 2 addresses in the constructor 
        let account = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");
        let fake_input: Address = account.parse().expect("unable to parse account address");
        let fake_input = (fake_input,fake_input);
        // 2) get mock of the deploy params 
        let tx = get_deploy_params("Enigma");
        // 3) connect to ethereum network 
        let (eloop,w3) = connect();
        // 4) deploy the contract
        w3utils::deploy_contract(&w3, tx,fake_input).unwrap();
     }
     #[test]
     //#[ignore]
     fn test_deployed_contract(){
         // deploy the dummy contract 
         let (eloop,w3) = connect();
         let contract = deploy_dummy(&w3);
         // the deployed contract address
         let address = contract.address();
         let (abi,bytecode) = get_contract(&String::from("Dummy"));
         let contract = w3utils::deployed_contract(&w3, address , &abi).unwrap();
         let result = contract.query("mine", (), None, Options::default(), None);
         let param : U256 = result.wait().unwrap();
         assert_eq!(param.as_u64(), 1);
     }
 }