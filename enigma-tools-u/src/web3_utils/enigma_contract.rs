use failure::Error;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
//web3
use web3;
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::Http;
use web3::types::{Address, U256};
use web3::Web3;
//ethabi
use ethabi::Contract as ethabi_contract;
// enigma modules
use web3_utils::w3utils;
use common_u::errors;

pub struct EnigmaContract {
    pub web3: Web3<Http>,
    pub eloop: web3::transports::EventLoopHandle,
    pub w3_contract: Contract<Http>,
    pub abi_contract: ethabi_contract,
    pub account: Address,
}

impl EnigmaContract {
    pub fn new<P: AsRef<Path>>(address: &str, abi_path: P, account: &str, url: &str) -> Result<Self, Error> {
        let (eloop, web3) = w3utils::connect(url)?;
        let contract_address: Address = address.parse()?;
        let (w3_contract, abi_contract) = EnigmaContract::deployed(&web3, contract_address, abi_path)?;
        let account: Address = account.parse()?;

        Ok(EnigmaContract { web3, eloop, w3_contract, abi_contract, account })
    }

    // given a path load EnigmaContract.json
    pub fn load_contract_json<P: AsRef<Path>>(path: P) -> Result<String, Error> {
        let mut f = File::open(path)?;

        let mut json_contents = String::new();
        f.read_to_string(&mut json_contents)?;

        Ok(json_contents)
    }

    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider and ethabi
    pub fn deployed<P: AsRef<Path>>(web3: &Web3<Http>, address: Address, path: P) -> Result<(Contract<Http>, ethabi_contract), Error> {
        let contract_json = EnigmaContract::load_contract_json(path)?;
        let w3_contract = Contract::from_json(web3.eth(), address, &contract_json.as_bytes()).unwrap();
        let abi_contract = ethabi_contract::load(contract_json.as_bytes()).unwrap();
        Ok((w3_contract, abi_contract))
    }
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
