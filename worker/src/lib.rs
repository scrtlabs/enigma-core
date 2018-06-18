extern crate web3;
extern crate rustc_hex;
extern crate serde_json;

use std::fs::File;
use std::io::prelude::*;
use web3::Web3;
use web3::transports::Http;
use web3::types::Address;
use web3::contract::Contract;
use serde_json::Value;
use web3::types::H256;
use web3::types::U256;

pub fn select_worker(seed: U256, taskId: H256, blockNumber: U256) -> Address {
    /// TODO: config parameter
    let worker: Address = "9fbda871d559710256a2502a2517b794b482db40"
        .parse()
        .expect("unable to parse worker address");

    worker
}


pub struct EnigmaContract {
    w3: Web3<Http>,
    contract: Contract<Http>,
    account: Address,
}

/// For operations on the Enigma contract deployed on Ethereum
impl EnigmaContract {
    pub fn new(w3: Web3<Http>, address: &str, path: &str, account: &str) -> Self {
        let contract_address: Address = address
            .parse()
            .expect("unable to parse contract address");
        let contract = EnigmaContract::deployed(&w3, contract_address, path);

        let account: Address = account
            .parse()
            .expect("unable to parse account address");

        EnigmaContract { w3, contract, account }
    }

    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider
    fn deployed(w3: &Web3<Http>, address: Address, path: &str) -> Contract<Http> {
        let mut f = File::open(path)
            .expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");


        let v: Value = serde_json::from_str(&contents)
            .expect("unable to parse JSON built contract");

        let abi = serde_json::to_string(&v["abi"])
            .expect("unable to find the abi key at the root of the JSON built contract");

        println!("fetching contract deployed at {:?}, with abi: {}", address, abi);

        let contract = Contract::from_json(
            w3.eth(),
            address,
            abi.as_bytes(),
        ).expect("unable to fetch the deployed contract on the Ethereum provider");

        contract
    }

    /// Call the register transactional method of the Enigma contract
    /// Method signature: function register(bytes32 url, address signer, string quote)
    pub fn register(&self, url: &str, signer: &str, quote: &str) -> String {
//        self.contract.call("register", (self.account,), self.account, Option::default());
        String::from("register")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use web3::api::Web3;

    fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545")
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
    }

    #[test]
    fn it_registers() {
        let (_, w3) = setup();

        let contract = EnigmaContract::new(
            w3,
            "eec918d74c746167564401103096d45bbd494b74",
            "/Users/fredfortier/Code/enigma/mvp0/coin-mixer-poc/dapp/build/contracts/Enigma.json",
            "627306090abab3a6e1400e9345bc60c78a8bef57",
        );
        let url = "127.0.0.1";
        let signer = "0xecfcab0a285d3380e488a39b4bb21e777f8a4eac";
        let quote = "some big blog of text";
        let tx = contract.register(url, signer, quote);
        assert!(tx.len() > 0);
    }

    #[test]
    fn it_selects_worker() {
        let seed = U256::from(100);
        let w3 = Web3{ transport: () };
        let taskId = w3.sha3(b"test");
    }
}

