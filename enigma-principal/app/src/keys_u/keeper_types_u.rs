use std::vec::Vec;

use bigint;
use ethabi::{Address, Bytes, encode, Hash, Token};
use ethereum_types::{H160, U256, U64};
use failure::Error;
pub use rlp::{Decodable, decode, DecoderError, UntrustedRlp};
use enigma_types::ContractAddress;

use enigma_crypto::hash::Keccak256;

pub trait FromBigint<T>: Sized {
    fn from_bigint(_: T) -> Self;
}



impl FromBigint<bigint::H160> for H160 { fn from_bigint(b: bigint::H160) -> Self { H160(b.0) } }

impl FromBigint<bigint::U256> for U256 { fn from_bigint(b: bigint::U256) -> Self { U256(b.0) } }


pub trait RawEncodable {
    fn raw_encode(&self) -> Result<Bytes, Error>;
}

#[derive(Debug, Clone)]
struct WorkerSelectionToken {
    pub seed: U256,
    pub sc_addr: ContractAddress,
    pub nonce: U256,
}

impl RawEncodable for WorkerSelectionToken {
    /// Encode the WorkerSelectionToken as Ethereum ABI parameters
    fn raw_encode(&self) -> Result<Bytes, Error> {
        let tokens = vec![
            Token::Uint(self.seed),
            Token::FixedBytes(self.sc_addr.to_vec()),
            Token::Uint(self.nonce),
        ];
        Ok(encode(&tokens))
    }
}

#[derive(Debug, Clone)]
pub struct InputWorkerParams {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub stakes: Vec<U256>,
}

impl InputWorkerParams {
    /// Run the worker selection algorithm against the current epoch
    ///
    /// # Arguments
    ///
    /// * `sc_addr` - The Secret Contract address
    /// * `seed` - The random seed for the selected epoch
    ///
    pub fn get_selected_worker(&self, sc_addr: ContractAddress, seed: U256) -> Result<Option<Address>, Error> {
        let worker = self.get_selected_workers(sc_addr, seed, None)?;
        if worker.is_empty() {
            Ok(None)
        } else {
            Ok(Some(worker[0].clone()))
        }
    }

    #[logfn(DEBUG)]
    fn get_selected_workers(&self, sc_addr: ContractAddress, seed: U256, group_size: Option<u64>) -> Result<Vec<Address>, Error> {
        let mut balance_sum = U256::zero();
        for &balance in &self.stakes {
            balance_sum += balance;
        }
        // Using the same type as the Enigma contract
        let mut nonce = U256::zero();
        let mut selected_workers = Vec::new();
        let group_size = group_size.unwrap_or(1);

        while selected_workers.len() < group_size as usize {
            let token = WorkerSelectionToken { seed, sc_addr, nonce };
            // This is equivalent to encodePacked in Solidity
            let hash = token.raw_encode()?.keccak256();
            let mut rand_val: U256 = U256::from(*hash) % balance_sum;
            println!("The initial random value: {:?}", rand_val);
            let mut selected_worker = self.workers.last().unwrap();

            for (i, worker) in self.workers.iter().enumerate() {
                let (new_rand, overflow) = rand_val.overflowing_sub(self.stakes[i]);
                if overflow || new_rand.is_zero() {
                    selected_worker = worker;
                    break;
                }
                rand_val = new_rand;
                println!("The next random value: {:?}", rand_val);
            }
            if !selected_workers.contains(selected_worker) {
                selected_workers.push(*selected_worker);
            }
            nonce += 1.into();
        }
        println!("The selected workers: {:?}", selected_workers);
        Ok(selected_workers)
    }
}

impl Decodable for InputWorkerParams {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            block_number: U256::from_bigint(rlp.val_at(0)?),
            workers: rlp.list_at(1)?.iter().map(|a| H160::from_bigint(*a)).collect::<Vec<H160>>(),
            stakes: rlp.list_at(2)?.iter().map(|b| U256::from_bigint(*b)).collect::<Vec<U256>>(),
        })
    }
}
