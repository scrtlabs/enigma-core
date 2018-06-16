extern crate web3;
extern crate rustc_hex;
extern crate mockers;
extern crate serde_json;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use web3::Web3;
use web3::transports::Http;
use web3::types::Address;
use std::time;
use std::thread;
use web3::futures::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use web3::contract::Contract;
use serde_json::{Value, Error};

/// Trying to make this an abstraction so the implementation can be externalized but
/// I'm not having any luck passing a Trait to Arc
pub trait Emittable
{
    fn new() -> Self;
    fn emit_epoch(&self, block: usize);
}

pub struct EpochGen {}

impl Emittable for EpochGen
{
    fn new() -> Self
    {
        EpochGen {}
    }

    fn emit_epoch(&self, block: usize)
    {
        println!("emitting epoch: {}", block);
    }
}

pub struct Ledger
{
    w3: Web3<Http>,
}

/// For operations on the Ethereum ledger
impl Ledger
{
    pub fn new(w3: Web3<Http>) -> Self
    {
        Ledger { w3 }
    }

    pub fn watch_blocks(&self, eloop: web3::transports::EventLoopHandle, epoch_generator: Arc<EpochGen>, max_rounds: usize)
    {
        let blocks_in_epoch: usize = 5;
        let block = Arc::new(AtomicUsize::new(0));
        for _ in 0..max_rounds {
            let block = Arc::clone(&block);
            let epoch_generator = epoch_generator.clone();
            let f = self.w3.eth().block_number().then(move |res| {
                match res {
                    Ok(n) => {
                        let cur_block = n.low_u64() as usize;
                        let ref_block = block.swap(cur_block, Ordering::Relaxed);
                        println!("the current block number: {}, ref block: {}", cur_block, ref_block);

                        if (ref_block == 0) | (ref_block + blocks_in_epoch <= cur_block) {
                            epoch_generator.emit_epoch(cur_block);
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }

                Ok(())
            });

            eloop.remote().spawn(|_| f);
            thread::sleep(time::Duration::from_secs(10));
        }
    }
}

pub struct EnigmaContract
{
    w3: Web3<Http>,
    contract: Contract<Http>,
}

/// For operations on the Enigma contract deployed on Ethereum
impl EnigmaContract
{
    pub fn new(w3: Web3<Http>, address: &str, path: &str) -> Self
    {
        let contract = EnigmaContract::deployed(&w3, address, path);
        EnigmaContract { w3, contract }
    }

    /// Fetch the Enigma contract deployed on Ethereum using an HTTP Web3 provider
    fn deployed(w3: &Web3<Http>, address: &str, path: &str) -> Contract<Http>
    {
        let mut f = File::open(path)
            .expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");

        let contract_address: Address = address
            .parse()
            .unwrap();

        let v: Value = serde_json::from_str(&contents).unwrap();
        let abi = serde_json::to_string(&v["abi"]).unwrap();
        println!("fetching contract deployed at {:?}, with abi: {}", contract_address, abi);

        let contract = Contract::from_json(
            w3.eth(),
            contract_address,
            abi.as_bytes(),
        ).unwrap();

        contract
    }

    /// Call the register transactional method of the Enigma contract
    pub fn register(&self) -> String
    {
        String::from("register")
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use mockers::Scenario;

    fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>)
    {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545").unwrap();
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
    }

    #[test]
    fn it_registers()
    {
        let (_, w3) = setup();

        let contract = EnigmaContract::new(w3, "eec918d74c746167564401103096d45bbd494b74", "/Users/fredfortier/Code/enigma/mvp0/coin-mixer-poc/dapp/build/contracts/Enigma.json");
        let tx = contract.register();
        assert!(tx.len() > 0);
    }

    #[test]
    fn it_watch_blocks()
    {
        let (eloop, w3) = setup();
        let ledger = Ledger::new(w3);
        let eg = EpochGen::new();

        let epoch_generator = Arc::new(eg);
        ledger.watch_blocks(eloop, epoch_generator, 3);
    }
}
