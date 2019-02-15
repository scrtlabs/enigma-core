use ethabi::{Address, Hash, Token, encode, Bytes};
use std::vec::Vec;
use eth_tools_t::keeper_types_t::InputWorkerParams;
use ethereum_types::{H160, U256, H256, U64};
use common::errors_t::EnclaveError;
use bigint;
use enigma_crypto::hash::Keccak256;

pub trait IntoBigint<T> {
    fn bigint(self) -> T;
}

impl IntoBigint<bigint::U256> for U256 { fn bigint(self) -> bigint::U256 { bigint::U256(self.0) } }

impl IntoBigint<bigint::H256> for H256 { fn bigint(self) -> bigint::H256 { bigint::H256(self.0) } }

pub type EpochNonce = [u8; 32];

pub trait PackedEncodable {
    fn encode_packed(&self) -> Result<Bytes, EnclaveError>;
}

#[derive(Debug, Clone)]
struct WorkerSelectionToken {
    pub seed: U256,
    pub sc_addr: Hash,
    pub nonce: U256,
}

impl PackedEncodable for WorkerSelectionToken {
    fn encode_packed(&self) -> Result<Bytes, EnclaveError> {
        let tokens = vec![
            Token::Uint(self.seed),
            Token::FixedBytes(self.sc_addr.0.to_vec()),
            Token::Uint(self.nonce),
        ];
        Ok(encode(&tokens))
    }
}

#[derive(Debug, Clone)]
pub struct Epoch {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub stakes: Vec<U256>,
    pub nonce: U256,
    pub seed: U256,
}

impl Epoch {
    pub fn new(params: InputWorkerParams, nonce: U256, seed: U256) -> Result<Epoch, EnclaveError> {
        Ok(Epoch {
            block_number: params.block_number,
            workers: params.workers,
            stakes: params.stakes,
            nonce: nonce,
            seed: seed,
        })
    }

    pub fn get_selected_workers(&self, sc_addr: H256, group_size: Option<U64>) -> Result<Vec<Address>, EnclaveError> {
        let workers = self.workers.to_vec();
        let mut balance_sum: U256 = U256::from(0);
        for balance in self.stakes.clone() {
            balance_sum = balance_sum + balance;
        }
        // Using the same type as the Enigma contract
        let mut nonce = U256::from(0);
        let mut selected_workers: Vec<H160> = Vec::new();
        while {
            let token = WorkerSelectionToken { seed: self.seed, sc_addr, nonce };
            // This is equivalent to encodePacked in Solidity
            let hash: [u8; 32] = token.encode_packed()?.keccak256().into();
            let mut rand_val: U256 = U256::from(hash) % balance_sum;
            println!("The initial random value: {:?}", rand_val);
            let mut selected_worker = self.workers[self.workers.len() - 1];
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

impl PackedEncodable for Epoch {
    fn encode_packed(&self) -> Result<Bytes, EnclaveError> {
        let tokens = vec![
            Token::Uint(self.seed),
            Token::Uint(self.nonce),
            Token::Array(self.workers.iter().map(|a| Token::Address(*a)).collect()),
            Token::Array(self.stakes.iter().map(|s| Token::Uint(*s)).collect()),
        ];
        Ok(encode(&tokens))
    }
}
