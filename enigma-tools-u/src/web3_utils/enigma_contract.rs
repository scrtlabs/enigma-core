use failure::Error;
use std::path::Path;
use std::fs::File;
use std::str::FromStr;
use std::io::prelude::*;
use web3;
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::Http;
use web3::types::{Address, U256, H160};
use web3::Web3;
use std::sync::Arc;
use crate::web3_utils::w3utils;
use crate::common_u::errors;


// This should be used as the main Web3/EventLoop
// Creating another one means more threads and more thing to handle.
// Important!! When the eloop is dropped the Web3/Contract will stop work!
#[derive(Debug)]
pub struct EnigmaContract {
    pub web3: Arc<Web3<Http>>,
    pub eloop: web3::transports::EventLoopHandle,
    pub w3_contract: Contract<Http>,
    pub account: Address,
}

impl EnigmaContract {
    pub fn new<P: AsRef<Path>>(contract_address: &str, abi_path: P, account: Option<&str>, url: &str) -> Result<Self, Error> {
        let (eloop, web3) = w3utils::connect(url)?;
        let w3_contract = EnigmaContract::from_deployed(&web3, contract_address, abi_path)?;
        let account: Address = match account {
            Some(a) => a.parse()?,
            None => web3.eth().accounts().wait().unwrap()[0], // TODO: Do something with this unwrapping
        };
        Ok(EnigmaContract { web3: Arc::new(web3), eloop, w3_contract, account })
    }

    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider and ethabi
    pub fn from_deployed<P: AsRef<Path>>(web3: &Web3<Http>, address: &str, path: P) -> Result<Contract<Http>, Error> {

        let (abi_json, _bytecode) = w3utils::load_contract_abi_bytecode(path)?;
        let w3_contract = Contract::from_json(web3.eth(), address.parse()?, abi_json.as_bytes()).unwrap();
        Ok(w3_contract)
    }

    pub fn deploy_contract<P: AsRef<Path>>(token_path: P, enigma_path: P, ethereum_url: &str, account: Option<&str>, sgx_address: &str) -> Result<Self, Error> {
        let (enigma_abi, enigma_bytecode) = w3utils::load_contract_abi_bytecode(enigma_path)?;
        let (token_abi, token_bytecode) = w3utils::load_contract_abi_bytecode(token_path)?;

        let (eloop, w3) = w3utils::connect(ethereum_url)?;

        let account: Address = match account {
            Some(a) => a.parse()?,
            None => w3.eth().accounts().wait().unwrap()[0], // TODO: Do something with this unwrapping
        };
        let deployer = &account.hex()[2..];
        let mut deploy_params = w3utils::DeployParams::new(deployer, token_abi, token_bytecode, 5999999, 1, 0)?;
        let token_contract = w3utils::deploy_contract(&w3, &deploy_params, ())?;

        deploy_params.bytecode = enigma_bytecode;
        deploy_params.abi = enigma_abi;

        let signer: H160 = sgx_address.parse()?;
        let enigma_contract = w3utils::deploy_contract(&w3, &deploy_params, (token_contract.address(), signer))?;

        let web3 = Arc::new(w3);

        Ok(EnigmaContract { web3, eloop, w3_contract: enigma_contract, account })
    }

    pub fn address(&self) -> Address { self.w3_contract.address() }

}

pub trait ContractFuncs {
    // register
    // input: _signer: Address, _report: bytes
    fn register(&self, signer: &str, report: &[u8], gas: u64) -> Result<(), Error>;

    // setWorkersParams
    // input: _seed: U256, _sig: bytes
    fn set_workers_params(&self, _seed: u64, _sig: &[u8], gas: u64)-> Result<(), Error>;
}

impl ContractFuncs for EnigmaContract {

    fn register(&self, signer: &str, report: &[u8], gas: u64) -> Result<(), Error> {
        // register
        let signer_addr: Address = signer.parse()?;
        let mut opts = Options::default();
        opts.gas = Some(gas.into());
        // call the register function
        match self.w3_contract
            .call("register", (signer_addr, report.to_vec()), self.account, opts)
            .wait() {
            Ok(_) => Ok(()),
            Err(e) => Err(errors::Web3Error{ message: String::from("error when trying to register- unable to call contract") }.into()),
        }
    }

    fn set_workers_params(&self, _seed: u64, _sig: &[u8], gas: u64)-> Result<(), Error>{
        let mut opts: Options = Options::default();
        opts.gas = Some(gas.into());

        let seed: U256 = _seed.into();
        self.w3_contract.call("setWorkersParams", (seed, _sig.to_vec()), self.account, opts).wait().unwrap();
        Ok(())
    }
}
