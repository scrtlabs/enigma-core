use std::fs::File;
use std::path::Path;
use std::str;
use std::sync::Arc;
use std::time;

// general
use failure::Error;
use hex::{ToHex, FromHex};
use serde_json;
use serde_json::Value;
use web3;
use web3::contract::{Contract, Options};
use web3::contract::tokens::Tokenize;
use web3::futures::Future;
use web3::transports::{Http};
use web3::types::{Address, Log, U256};
use web3::types::BlockNumber;
use web3::types::FilterBuilder;
use web3::Web3;

use enigma_crypto::hash::Keccak256;

// files
use crate::common_u::errors;

pub struct DeployParams {
    pub deployer: Address,
    pub abi: String,
    pub gas_limit: U256,
    pub bytecode: String,
    pub poll_interval: u64,
    pub confirmations: usize,
}

impl DeployParams {
    pub fn new(deployer: &str, abi: String, bytecode: String, gas_limit: u64,
               poll_interval: u64, confirmations: usize, ) -> Result<Self, Error> {
        let gas_limit: U256 = gas_limit.into();

        let deployer: Address = deployer.parse()?;

        Ok(DeployParams { deployer, abi, gas_limit, bytecode, poll_interval, confirmations })
    }
}

// given a path load EnigmaContract.json and extract the ABI and the bytecode
pub fn load_contract_abi_bytecode<P: AsRef<Path>>(path: P) -> Result<(String, String), Error> {
    let f = File::open(path)?;
    let contract_data: Value = serde_json::from_reader(f)?;
    let abi = serde_json::to_string(&contract_data["abi"])?;
    let bytecode = serde_json::to_string(&contract_data["bytecode"])?;
    Ok((abi, bytecode))
}

pub fn load_contract_abi<P: AsRef<Path>>(path: P) -> Result<String, Error> {
    let f = File::open(path)?;
    let data: Value = serde_json::from_reader(f)?;
    Ok(serde_json::to_string(&data["abi"])?)
}

// Important!! Best Practice is to have only one Web3 Instance.
// Every time Web3::new() is called it spawns a new thread that is tied to eloop.
// Important!! When eloop is Dropped, the underlying Transport dies.
// https://github.com/tomusdrw/rust-web3/blob/master/src/transports/http.rs#L79
// Precision: This is true for Transport::new(), not Web3::new()
#[logfn(WARN)]
pub fn connect(url: &str) -> Result<(web3::transports::EventLoopHandle, Web3<Http>), Error> {
    let (_eloop, http) = match web3::transports::Http::new(url) {
        Ok((eloop, http)) => (eloop, http),
        Err(_) => return Err(errors::Web3Error { message: String::from("unable to create an http connection") }.into()),
    };
    let w3 = web3::Web3::new(http);
    Ok((_eloop, w3))
}

// connect to an existing deployed smart contract
pub fn deployed_contract(web3: &Web3<Http>, contract_addr: Address, abi: &[u8]) -> Result<Contract<Http>, Error> {
    match Contract::from_json(web3.eth(), contract_addr, abi) {
        Ok(contract) => Ok(contract),
        Err(_) => Err(errors::Web3Error { message: String::from("unable to create a contract") }.into()),
    }
}

// private:: truncate the bytecode from solidity json
// this method does 2 things:
// 1) web3 requires byte array of the hex byte code from_hex
// 2) serde_json reads the bytecode as string with '"0x..."' so 4 chars needs to be removed.
// TODO:: solve the fact that serde doesnt ignore `"`
pub fn truncate_bytecode(bytecode: &str) -> Result<Vec<u8>, Error> {
    // TODO: this does not work with linked libraries and probably should be handled be web3
    let b = bytecode.as_bytes();
    let sliced = &b[3..b.len() - 1];
    let result = str::from_utf8(&sliced.to_vec()).unwrap().from_hex()?;
    Ok(result)
}

// deploy any smart contract
pub fn deploy_contract<P>(web3: &Web3<Http>, tx_params: &DeployParams, ctor_params: P) -> Result<Contract<Http>, Error>
    where P: Tokenize {
    let bytecode: Vec<u8> = truncate_bytecode(&tx_params.bytecode)?;

    let deployer_addr = tx_params.deployer;
    let mut options = Options::default();
    options.gas = Some(tx_params.gas_limit);

    let builder = Contract::deploy(web3.eth(), tx_params.abi.as_bytes())
        .unwrap()
        .confirmations(tx_params.confirmations)
        .poll_interval(time::Duration::from_secs(tx_params.poll_interval));

    match builder.options(options).execute(bytecode.to_hex(), ctor_params, deployer_addr) {
        Ok(builder) => {
            let contract = builder.wait().unwrap();
            println!("deployed contract at address = {}", contract.address());
            Ok(contract)
        }
        Err(_) => Err(errors::Web3Error { message: String::from("unable to deploy the contract") }.into()),
    }
}

//////////////////////// EVENTS LISTENING START ///////////////////////////

fn build_event_filter(event_name: &str, contract_addr: Option<&str>) -> web3::types::Filter {
    let filter = FilterBuilder::default()
        .topics(Some(vec![(*event_name.as_bytes().keccak256()).into()]), None, None, None)
        .from_block(BlockNumber::Earliest)
        .to_block(BlockNumber::Latest);
    match contract_addr {
        Some(addr) => filter.address(vec![addr.parse().unwrap()]).build(),
        None => filter.build(),
    }
}

/// TESTING: filter the network for events
pub fn filter_blocks(w3: &Arc<Web3<Http>>, contract_addr: Option<&str>, event_name: &str) -> Result<Vec<Log>, Error> {
    let filter = build_event_filter(event_name, contract_addr);

    match w3.eth().logs(filter).wait() {
        Ok(logs) => Ok(logs),
        Err(_) => Err(errors::Web3Error { message: String::from("unable to retrieve logs") }.into()),
    }
}
// TODO:: implement this function, it should work but needs more improvements and of course a future from the outside as a parameter.
// pub fn filter_blocks_async(contract_addr : String ,url : String){
//     let (eloop,w3) = connect(&url.as_str())
//         .expect("cannot connect to ethereum");

//     let contract_addr = contract_addr.clone();
//     //"Hello(address)"
//     // let filter = build_event_fuilder(String::from("Hello(address)"),Some(contract_addr.clone()));
//     let filter = build_event_fuilder(String::from("Hello(address)"),None);

//     let future = w3.eth()
//             .logs(filter)
//             .then(move |res|{
//                 match res {
//                     Ok(logs)=>{
//                         println!("Ok got log  {:?}", logs );
//                     },
//                     Err(e) =>{
//                         println!("Err got log {:?} ",e );
//                     },
//                 }

//             Ok(())
//         });
//         eloop.remote().spawn(|_| future);
//         loop{
//           thread::sleep(time::Duration::from_secs(1));
//         }
// }
//////////////////////// EVENTS LISTENING END ///////////////////////////

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    extern crate rustc_hex;

    use std::env;

    use web3_utils::w3utils;

    use super::*;

    use self::rustc_hex::ToHex;

    /// This function is important to enable testing both on the CI server and local.
        /// On the CI Side:
        /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
        /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
        /// The default is set to ganache cli "http://localhost:8545"
    fn get_node_url() -> String { env::var("NODE_URL").unwrap_or("http://localhost:9545".to_string()) }

    // helper: given a contract name return the bytecode and the abi
    fn get_contract(ctype: &str) -> (String, String) {
        let path = env::current_dir().unwrap();
        println!("The current directory is {}", path.display());

        let enigma_token = "./src/tests/web3_tests/contracts/EnigmaToken.json";
        let enigma = "./src/tests/web3_tests/contracts/Enigma.json";
        let dummy = "./src/tests/web3_tests/contracts/Dummy.json";

        let to_load = match ctype.as_ref() {
            "EnigmaToken" => enigma_token,
            "Enigma" => enigma,
            "Dummy" => dummy,
            _ => "",
        };
        assert_ne!(to_load, "", "wrong contract type");

        let (abi, bytecode) = w3utils::load_contract_abi_bytecode(to_load).unwrap();
        (abi, bytecode)
    }

    // helper to quickly mock params for deployment of a contract to generate DeployParams
    fn get_deploy_params(account: Address, ctype: &str) -> w3utils::DeployParams {
        let deployer = account.to_fixed_bytes().to_hex();
        let gas_limit: u64 = 5999999;
        let poll_interval: u64 = 1;
        let confirmations: usize = 0;
        let (abi, bytecode) = get_contract(&ctype.to_string());
        w3utils::DeployParams::new(&deployer, abi, bytecode, gas_limit, poll_interval, confirmations).unwrap()
    }

    // helper connect to web3
    fn connect() -> (web3::transports::EventLoopHandle, Web3<Http>, Vec<Address>) {
        let uri = get_node_url();
        let (eloop, w3) = w3utils::connect(&uri).unwrap();
        let accounts = w3.eth().accounts().wait().unwrap();
        (eloop, w3, accounts)
    }

    // helper deploy a dummy contract and return the contract instance
    fn deploy_dummy(w3: &Web3<Http>, account: Address) -> Contract<Http> {
        let tx = get_deploy_params(account, "Dummy");
        let contract = w3utils::deploy_contract(&w3, &tx, ()).unwrap();
        contract
    }

    #[test]
    //#[ignore]
    fn test_deploy_dummy_contract() {
        let (_eloop, w3, accounts) = connect();
        let contract = deploy_dummy(&w3, accounts[0]);
        // validate deployment
        // mine func add to a uint256=0 1 and returns it's value
        let result = contract.query("mine", (), None, Options::default(), None);
        let param: U256 = result.wait().unwrap();
        assert_eq!(param.as_u64(), 1);
    }

    #[test]
    //#[ignore]
    fn test_deploy_enigma_contract() {
        // 1) generate ctor input
        // the enigma contract requires 2 addresses in the constructor
        let account = String::from("627306090abab3a6e1400e9345bc60c78a8bef57");
        let fake_input: Address = account.parse().expect("unable to parse account address");
        let fake_input = (fake_input.clone(), fake_input);
        // 2) connect to ethereum network
        let (_eloop, w3, accounts) = connect();
        // 3) get mock of the deploy params
        let tx = get_deploy_params(accounts[0], "Enigma");
        // 4) deploy the contract
        w3utils::deploy_contract(&w3, &tx, fake_input).unwrap();
    }

    #[test]
    //#[ignore]
    fn test_deployed_contract() {
        // deploy the dummy contract
        let (_eloop, w3, accounts) = connect();
        let contract = deploy_dummy(&w3, accounts[0]);
        // the deployed contract address
        let address = contract.address();
        let (abi, _) = get_contract(&String::from("Dummy"));
        let contract = w3utils::deployed_contract(&w3, address, abi.as_bytes()).unwrap();
        let result = contract.query("mine", (), None, Options::default(), None);
        let param: U256 = result.wait().unwrap();
        assert_eq!(param.as_u64(), 1);
    }
}
