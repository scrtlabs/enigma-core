use crate::common_u::errors;
use crate::web3_utils::w3utils;
use failure::Error;
use hex::ToHex;
use std::path::Path;
use std::sync::Arc;
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, H160, U256, H256, Bytes};
use web3::Web3;
use std::str;

// This should be used as the main Web3/EventLoop
// Creating another one means more threads and more thing to handle.
// Important!! When the eloop is dropped the Web3/Contract will stop work!
#[derive(Debug)]
pub struct EnigmaContract {
    pub web3: Arc<Web3<Http>>,
    pub eloop: EventLoopHandle,
    pub w3_contract: Contract<Http>,
    pub account: Address,
}

impl EnigmaContract {
    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider and ethabi
    #[logfn(INFO)]
    pub fn from_deployed<P: AsRef<Path>>(contract_address: &str, abi_path: P,
                                         account: Option<&str>, url: &str) -> Result<Self, Error> {
        let (eloop, web3) = w3utils::connect(url)?;
        Self::from_deployed_web3(contract_address, abi_path, account, web3, eloop)
    }

    pub fn from_deployed_web3<P: AsRef<Path>>(contract_address: &str, abi_path: P, account: Option<&str>,
                                              web3: Web3<Http>, eloop: EventLoopHandle) -> Result<Self, Error> {
        let account: Address = match account {
            Some(a) => a.parse()?,
            None => web3.eth().accounts().wait().unwrap()[0], // TODO: Do something with this unwrapping
        };
        let (abi_json, _bytecode) = w3utils::load_contract_abi_bytecode(abi_path)?;
        let w3_contract = Contract::from_json(web3.eth(), contract_address.parse()?, abi_json.as_bytes()).unwrap();
        Ok(EnigmaContract { web3: Arc::new(web3), eloop, w3_contract, account })
    }

    #[logfn(INFO)]
    pub fn deploy_contract<P: AsRef<Path>>(token_path: P, enigma_path: P, ethereum_url: &str,
                                           account: Option<&str>, sgx_address: &str) -> Result<Self, Error> {
        let (enigma_abi, enigma_bytecode) = w3utils::load_contract_abi_bytecode(enigma_path)?;
        let (token_abi, token_bytecode) = w3utils::load_contract_abi_bytecode(token_path)?;

        let (eloop, w3) = w3utils::connect(ethereum_url)?;

        let account: Address = match account {
            Some(a) => a.parse()?,
            None => w3.eth().accounts().wait().unwrap()[0], // TODO: Do something with this unwrapping
        };
        let deployer = &account.to_hex();
        let mut deploy_params = w3utils::DeployParams::new(deployer, token_abi, token_bytecode, 5_999_999, 1, 0)?;
        let token_contract = w3utils::deploy_contract(&w3, &deploy_params, ())?;

        deploy_params.bytecode = enigma_bytecode;
        println!("The Enigma bytecode: {:?}", deploy_params.bytecode);
        deploy_params.abi = enigma_abi;

        let signer: H160 = sgx_address.parse()?;
        let enigma_contract = w3utils::deploy_contract(&w3, &deploy_params, (token_contract.address(), signer))?;

        let web3 = Arc::new(w3);

        Ok(EnigmaContract { web3, eloop, w3_contract: enigma_contract, account })
    }

    pub fn address(&self) -> Address { self.w3_contract.address() }
}

pub trait ContractFuncs<G> {
    // register
    // input: _signer: Address, _report: bytes
    fn register(&self, signer: &str, report: &[u8], signature: &str, gas: G) -> Result<H256, Error>;

    // setWorkersParams
    // input: _seed: U256, _sig: bytes
    fn set_workers_params(&self, _seed: u64, _sig: &[u8], gas: G) -> Result<H256, Error>;
}

impl<G: Into<U256>> ContractFuncs<G> for EnigmaContract {
    fn register(&self, signer: &str, report: &[u8], signature: &str, gas: G) -> Result<H256, Error> {
        // register
        let signer_addr: Address = signer.parse()?;
        let mut opts = Options::default();
        opts.gas = Some(gas.into());
        // call the register function
        let sig = signature.as_bytes().to_vec();
//        println!("Calling the registed fn: {:?}: {:?} {:?}", signer_addr, report.to_vec(), sig);
        match self.w3_contract.call("register", (signer_addr, report.to_vec(), sig), self.account, opts).wait() {
            Ok(tx) => Ok(tx),
            Err(e) => {
                Err(errors::Web3Error { message: format!("Unable to call register: {:?}", e) }.into())
            }
        }
    }

    #[logfn(INFO)]
    fn set_workers_params(&self, _seed: u64, _sig: &[u8], gas: G) -> Result<H256, Error> {
        let mut opts: Options = Options::default();
        opts.gas = Some(gas.into());
        let seed: U256 = _seed.into();
        match self.w3_contract
            .call("setWorkersParams", (seed, _sig.to_vec()), self.account, opts)
            .wait() {
            Ok(tx) => Ok(tx),
            Err(e) => Err(errors::Web3Error { message: format!("Unable to call setWorkerParams: {:?}", e) }.into()),
        }
    }
}
