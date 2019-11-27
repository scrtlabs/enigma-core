#![allow(missing_docs)] // This should be removed after @fredfortier will document this module.

use crate::localstd::{vec, vec::Vec};
use log::debug;
use log_derive::logfn;

use bigint;
use crate::ethabi::{encode, Address, Bytes, Token};
use crate::ethereum_types::{H160, U256};
use enigma_crypto::hash::Keccak256;
use enigma_types::ContractAddress;
pub use rlp::{decode, encode as rlpEncode, Encodable, Decodable, DecoderError, UntrustedRlp, RlpStream};

pub const EPOCH_CAP: usize = 2;

pub trait FromBigint<T>: Sized {
    fn from_bigint(_: T) -> Self;
}

impl FromBigint<bigint::H160> for H160 {
    fn from_bigint(b: bigint::H160) -> Self { H160(b.0) }
}

impl FromBigint<bigint::U256> for U256 {
    fn from_bigint(b: bigint::U256) -> Self { U256(b.0) }
}

pub trait RawEncodable {
    fn raw_encode(&self) -> Bytes;
}

#[derive(Clone)]
struct WorkerSelectionToken {
    pub seed: U256,
    pub sc_addr: ContractAddress,
    pub nonce: U256,
}

impl RawEncodable for WorkerSelectionToken {
    /// Encode the WorkerSelectionToken as Ethereum ABI parameters
    fn raw_encode(&self) -> Bytes {
        let tokens = vec![Token::Uint(self.seed), Token::FixedBytes(self.sc_addr.to_vec()), Token::Uint(self.nonce)];
        encode(&tokens)
    }
}

#[derive(Debug, Clone)]
pub struct InputWorkerParams {
    pub km_block_number: U256,
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
    #[logfn(DEBUG)]
    pub fn get_selected_worker(&self, sc_addr: ContractAddress, seed: U256) -> Option<Address> {
        debug!("Finding selected worker for sc_addr: {:?} and seed: {:?}", sc_addr, seed);
        let workers = self.get_selected_workers(sc_addr, seed, None);
        if workers.is_empty() {
            None
        } else {
            Some(workers[0])
        }
    }

    #[logfn(DEBUG)]
    fn get_selected_workers(&self, sc_addr: ContractAddress, seed: U256, group_size: Option<u64>) -> Vec<Address> {
        let mut selected_workers = Vec::new();
        if self.workers.is_empty() || self.workers.len() != self.stakes.len() {
            debug!("Invalid worker selection parameters {:?}", self);
            return selected_workers;
        }
        let mut balance_sum = U256::zero();
        for &balance in &self.stakes {
            balance_sum += balance;
        }
        // Using the same type as the Enigma contract
        let mut nonce = U256::zero();
        let group_size = group_size.unwrap_or(1);

        while selected_workers.len() < group_size as usize {
            let token = WorkerSelectionToken { seed, sc_addr, nonce };
            // This is equivalent to encodePacked in Solidity
            let hash = token.raw_encode().keccak256();
            let mut rand_val: U256 = U256::from(*hash) % balance_sum;
            debug!("The initial random value: {:?}", rand_val.0);
            let mut selected_worker = self.workers.last().unwrap();

            for (i, worker) in self.workers.iter().enumerate() {
                let (new_rand, overflow) = rand_val.overflowing_sub(self.stakes[i]);
                if overflow || new_rand.is_zero() {
                    selected_worker = worker;
                    break;
                }
                rand_val = new_rand;
                debug!("The next random value: {:?}", rand_val.0);
            }
            if !selected_workers.contains(selected_worker) {
                selected_workers.push(*selected_worker);
            }
            nonce += 1.into();
        }
        debug!("The selected workers: {:?}", selected_workers);
        selected_workers
    }
}

impl Decodable for InputWorkerParams {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            km_block_number: U256::from_bigint(rlp.val_at(0)?),
            workers: rlp.list_at(1)?.iter().map(|a| H160::from_bigint(*a)).collect::<Vec<_>>(),
            stakes: rlp.list_at(2)?.iter().map(|b| U256::from_bigint(*b)).collect::<Vec<_>>(),
        })
    }
}

impl Encodable for InputWorkerParams {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&bigint::U256(self.km_block_number.0));
        s.append_list(&self.workers.iter().map(|a| bigint::H160(a.0)).collect::<Vec<_>>());
        s.append_list(&self.stakes.iter().map(|b| bigint::U256(b.0)).collect::<Vec<_>>());
    }
}
