use std::path::Path;
use std::str;
use std::sync::Arc;

use failure::Error;
use hex::{FromHex, ToHex};
use web3::contract::{Contract, Options};
use web3::futures::Future;
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, Bytes, H160, H256, TransactionReceipt, U256};
use web3::Web3;

use enigma_types::ContractAddress;

use crate::common_u::errors;
use crate::web3_utils::w3utils;
use super::contract_ext::signed_call_with_confirmations;

// This should be used as the main Web3/EventLoop
// Creating another one means more threads and more things to handle.
// Important!! When the eloop is dropped the Web3/Contract will stop to work!
#[derive(Debug)]
pub struct EnigmaContract {
    pub web3: Arc<Web3<Http>>,
    pub eloop: EventLoopHandle,
    pub w3_contract: Contract<Http>,
    ethabi_contract: ethabi::Contract, // This should match the `ethabi::Contract` in `self.web3_contract`
    pub account: Address,
}

impl EnigmaContract {
    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider and ethabi
    #[logfn(INFO)]
    pub fn from_deployed<P: AsRef<Path>>(
        contract_address: &str,
        abi_path: P,
        account: Option<&str>,
        url: &str
    ) -> Result<Self, Error> {
        let (eloop, web3) = w3utils::connect(url)?;
        Self::from_deployed_web3(contract_address, abi_path, account, web3, eloop)
    }

    pub fn from_deployed_web3<P: AsRef<Path>>(
        contract_address: &str,
        abi_path: P,
        account: Option<&str>,
        web3: Web3<Http>,
        eloop: EventLoopHandle
    ) -> Result<Self, Error> {
        let account: Address = match account {
            Some(a) => a.parse()?,
            None => web3.eth().accounts().wait()?[0],
        };
        let abi_json = w3utils::load_contract_abi(abi_path)?;
        let ethabi_contract = ethabi::Contract::load(abi_json.as_bytes()).map_err(|e| failure::err_msg(e.to_string()))?;
        let w3_contract = Contract::new(web3.eth(), contract_address.parse()?, ethabi_contract.clone());
        Ok(EnigmaContract { web3: Arc::new(web3), eloop, w3_contract, ethabi_contract, account })
    }

    #[logfn(INFO)]
    pub fn deploy_contract<P: AsRef<Path>>(
        token_path: P,
        enigma_path: P,
        ethereum_url: &str,
        account: Option<&str>,
        sgx_address: &str
    ) -> Result<Self, Error> {
        let (enigma_abi, enigma_bytecode) = w3utils::load_contract_abi_bytecode(enigma_path)?;
        let (token_abi, token_bytecode) = w3utils::load_contract_abi_bytecode(token_path)?;

        let (eloop, w3) = w3utils::connect(ethereum_url)?;

        let account: Address = match account {
            Some(a) => a.parse()?,
            None => w3.eth().accounts().wait()?[0],
        };
        let deployer = &account.to_fixed_bytes().to_hex();
        let mut deploy_params = w3utils::DeployParams::new(deployer, token_abi, token_bytecode, 5_999_999, 1, 0)?;
        let token_contract = w3utils::deploy_contract(&w3, &deploy_params, ())?;

        let ethabi_contract = ethabi::Contract::load(enigma_abi.as_bytes()).map_err(|e| failure::err_msg(e.to_string()))?;
        deploy_params.bytecode = enigma_bytecode;
        deploy_params.abi = enigma_abi;

        let signer: H160 = sgx_address.parse()?;
        let enigma_contract = w3utils::deploy_contract(&w3, &deploy_params, (token_contract.address(), signer))?;

        let web3 = Arc::new(w3);

        Ok(EnigmaContract { web3, eloop, w3_contract: enigma_contract, ethabi_contract, account })
    }

    pub fn address(&self) -> Address { self.w3_contract.address() }
}

pub trait ContractFuncs<G> {
    // register
    // input: _signer: Address, _report: bytes
    fn register(&self, signing_address: H160, report: String, signature: String, gas: G, confirmations: usize) -> Result<TransactionReceipt, Error>;

    // setWorkersParams
    // input: _seed: U256, _sig: bytes
    fn set_workers_params(&self, block_number: U256, seed: U256, sig: Bytes, gas: G, confirmations: usize) -> Result<TransactionReceipt, Error>;
}

impl<G: Into<U256>> ContractFuncs<G> for EnigmaContract {
    #[logfn(DEBUG)]
    fn register(&self, signing_address: H160, report: String, signature: String, gas: G, confirmations: usize) -> Result<TransactionReceipt, Error> {
        // register
        let mut opts = Options::default();
        opts.gas = Some(gas.into());
        // call the register function
        let report = report.as_bytes().to_vec();
        let signature = signature.from_hex()?;
        let call = signed_call_with_confirmations(
            &self.web3,
            &self.ethabi_contract,
            self.w3_contract.address(),
            H256([0; 32]), // TODO set to a real key
            self.account,
            "register",
            (signing_address, report, signature),
            opts,
            /* chain_id */ 1, // TODO get this from configuration
            confirmations,
        )?;

        let receipt = call.wait().map_err(|e|
            errors::Web3Error { message: format!("Unable to call register: {:?}", e) }
        )?;
        Ok(receipt)
    }

    #[logfn(DEBUG)]
    fn set_workers_params(&self, block_number: U256, seed: U256, sig: Bytes, gas: G, confirmations: usize) -> Result<TransactionReceipt, Error> {
        let mut opts: Options = Options::default();
        opts.gas = Some(gas.into());

        let call = signed_call_with_confirmations(
            &self.web3,
            &self.ethabi_contract,
            self.w3_contract.address(),
            H256([0; 32]), // TODO set to a real key
            self.account,
            "setWorkersParams",
            (block_number, seed, sig.0),
            opts,
            /* chain_id */ 1, // TODO get this from configuration
            confirmations,
        )?;

        let receipt = call.wait().map_err(|e|
            errors::Web3Error { message: format!("Unable to call setWorkerParams: {:?}", e) }
        )?;
        Ok(receipt)
    }
}

pub trait ContractQueries {
    // getSigningAddress
    fn get_signing_address(&self) -> Result<H160, Error>;

    // getActiveWorkers
    // input: block_number
    fn get_active_workers(&self, block_number: U256) -> Result<(Vec<H160>, Vec<U256>), Error>;

    // countSecretContracts
    fn count_secret_contracts(&self) -> Result<U256, Error>;

    // getSecretContractAddresses
    // input: uint _start, uint _stop
    fn get_secret_contract_addresses(&self, start: U256, stop: U256) -> Result<Vec<ContractAddress>, Error>;

    // getAllSecretContractAddresses
    fn get_all_secret_contract_addresses(&self) -> Result<Vec<ContractAddress>, Error>;
}

impl ContractQueries for EnigmaContract {
    #[logfn(INFO)]
    fn get_signing_address(&self) -> Result<H160, Error> {
        println!("Fetching the signing address for account: {:?}", self.account);
        let signing_address: H160 =
            match self.w3_contract.query("getSigningAddress", (), self.account, Options::default(), None).wait() {
                Ok(addr) => addr,
                Err(e) => return Err(errors::Web3Error { message: format!("Unable to query getSigningAddress: {:?}", e) }.into()),
            };
        Ok(signing_address)
    }

    #[logfn(INFO)]
    fn get_active_workers(&self, block_number: U256) -> Result<(Vec<H160>, Vec<U256>), Error> {
        let worker_params: (Vec<Address>, Vec<U256>) =
            match self.w3_contract.query("getActiveWorkers", block_number, self.account, Options::default(), None).wait() {
                Ok(result) => result,
                Err(e) => return Err(errors::Web3Error { message: format!("Unable to query getActiveWorkers: {:?}", e) }.into()),
            };
        Ok(worker_params)
    }

    #[logfn(INFO)]
    fn count_secret_contracts(&self) -> Result<U256, Error> {
        let secret_contract_count: U256 =
            match self.w3_contract.query("countSecretContracts", (), self.account, Options::default(), None).wait() {
                Ok(count) => count,
                Err(e) => return Err(errors::Web3Error { message: format!("Unable to query countSecretContracts: {:?}", e) }.into()),
            };
        Ok(secret_contract_count)
    }

    #[logfn(INFO)]
    fn get_secret_contract_addresses(&self, start: U256, stop: U256) -> Result<Vec<ContractAddress>, Error> {
        let addrs: Vec<H256> =
            match self.w3_contract.query("getSecretContractAddresses", (start, stop), self.account, Options::default(), None).wait() {
                Ok(addrs) => addrs,
                Err(e) => {
                    return Err(errors::Web3Error { message: format!("Unable to query getSecretContractAddresses: {:?}", e) }.into())
                }
            };
        Ok(addrs.into_iter().map(|a|ContractAddress::from(a.0)).collect())
    }

    #[logfn(INFO)]
    fn get_all_secret_contract_addresses(&self) -> Result<Vec<ContractAddress>, Error> {
        self.w3_contract
            .query("getAllSecretContractAddresses", (),self.account, Options::default(), None)
            .wait()
            .map(|addrs: Vec<H256>| addrs.into_iter().map(|a| ContractAddress::from(a.0 )).collect())
            .map_err(|e| errors::Web3Error { message: format!("Unable to query getAllSecretContractAddresses: {:?}", e) }.into())
    }
}
