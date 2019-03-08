use bigint;
use bigint::H2048;
use ethabi::{Address, Bytes, encode, Hash, Token};
use ethereum_types::{H160, H256, H64, U256, U64};
pub use rlp::{Decodable, decode, DecoderError, UntrustedRlp};
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_crypto::hash::Keccak256;

pub trait FromBigint<T>: Sized {
    fn from_bigint(_: T) -> Self;
}

impl FromBigint<bigint::H64> for H64 { fn from_bigint(b: bigint::H64) -> Self { H64(b.0) } }

impl FromBigint<bigint::H256> for H256 { fn from_bigint(b: bigint::H256) -> Self { H256(b.0) } }

impl FromBigint<bigint::H160> for H160 { fn from_bigint(b: bigint::H160) -> Self { H160(b.0) } }

impl FromBigint<bigint::U256> for U256 { fn from_bigint(b: bigint::U256) -> Self { U256(b.0) } }

impl FromBigint<bigint::H2048> for H2048 { fn from_bigint(b: bigint::H2048) -> Self { H2048(b.0) } }

pub trait RawEncodable {
    fn raw_encode(&self) -> Result<Bytes, EnclaveError>;
}

#[derive(Debug, Clone)]
struct WorkerSelectionToken {
    pub seed: U256,
    pub sc_addr: Hash,
    pub nonce: U256,
}

impl RawEncodable for WorkerSelectionToken {
    /// Encode the WorkerSelectionToken as Ethereum ABI parameters
    fn raw_encode(&self) -> Result<Bytes, EnclaveError> {
        let tokens = vec![
            Token::Uint(self.seed),
            Token::FixedBytes(self.sc_addr.0.to_vec()),
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
    pub fn get_selected_worker(&self, sc_addr: H256, seed: U256) -> Result<Option<Address>, EnclaveError> {
        let worker = self.get_selected_workers(sc_addr, seed, None)?;
        if worker.is_empty() {
            Ok(None)
        } else {
            Ok(Some(worker[0].clone()))
        }
    }

    fn get_selected_workers(&self, sc_addr: H256, seed: U256, group_size: Option<U64>) -> Result<Vec<Address>, EnclaveError> {
        let workers = self.workers.to_vec();
        let mut balance_sum: U256 = U256::from(0);
        for balance in self.stakes.clone() {
            balance_sum = balance_sum + balance;
        }
        // Using the same type as the Enigma contract
        let mut nonce = U256::from(0);
        let mut selected_workers: Vec<H160> = Vec::new();
        while {
            let token = WorkerSelectionToken { seed, sc_addr, nonce };
            // This is equivalent to encodePacked in Solidity
            let hash: [u8; 32] = token.raw_encode()?.keccak256().into();
            let mut rand_val: U256 = U256::from(hash) % balance_sum;
            println!("The initial random value: {:?}", rand_val);
            let mut selected_worker = self.workers[self.workers.len() - 1].clone();
            for i in 0..self.workers.len() {
                let result = rand_val.overflowing_sub(self.stakes[i]);
                if result.1 == true || result.0 == U256::from(0) {
                    selected_worker = self.workers[i];
                    break;
                }
                rand_val = result.0;
                println!("The next random value: {:?}", rand_val);
            }
            if !selected_workers.contains(&selected_worker) {
                selected_workers.push(selected_worker);
            }
            nonce = nonce + U256::from(1);
            let limit = match group_size {
                Some(size) => size,
                None => U64::from(1),
            };
            U64::from(selected_workers.len()) < limit
        } {}
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
