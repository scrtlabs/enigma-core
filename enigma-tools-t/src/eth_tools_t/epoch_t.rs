use ethabi::{Address, Hash};
use std::vec::Vec;
use eth_tools_t::keeper_types_t::{InputWorkerParams};
use ethereum_types::{H160, U256, H256, U64};
use common::errors_t::EnclaveError;
use bigint;
use rlp::{Encodable, encode, RlpStream};
use enigma_crypto::hash::Keccak256;

pub trait IntoBigint<T> {
    fn bigint(self) -> T;
}

impl IntoBigint<bigint::U256> for U256 { fn bigint(self) -> bigint::U256 { bigint::U256(self.0) } }

impl IntoBigint<bigint::H256> for H256 { fn bigint(self) -> bigint::H256 { bigint::H256(self.0) } }

#[derive(Debug, Clone)]
struct WorkerSelectionToken {
    pub seed: U256,
    pub sc_addr: Hash,
    pub nonce: U256,
}

impl Encodable for WorkerSelectionToken {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.seed.bigint());
        s.append(&self.sc_addr.bigint());
        s.append(&self.nonce.bigint());
    }
}

#[derive(Debug, Clone)]
pub struct Epoch {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub balances: Vec<U256>,
    pub nonce: U256,
    pub seed: U256,
}

impl Epoch {
    pub fn new(params: InputWorkerParams, nonce: U256, seed: U256) -> Result<Epoch, EnclaveError> {
        Ok(Epoch{
            block_number: params.block_number,
            workers: params.workers,
            balances: params.balances,
            nonce: nonce,
            seed: seed,
        })
    }

    pub fn get_selected_workers(&self, sc_addr: H256, group_size: Option<U64>) -> Result<Vec<Address>, EnclaveError> {
        let workers = self.workers.to_vec();
        let mut balance_sum: U256 = U256::from(0);
        for balance in self.balances.clone() {
            balance_sum = balance_sum + balance;
        }
        // Using the same type as the Enigma contract
        let mut nonce = U256::from(0);
        let mut selected_workers: Vec<H160> = Vec::new();
        while {
            let token = WorkerSelectionToken { seed: self.seed, sc_addr, nonce };
            // This is equivalent to encodePacked in Solidity
            let hash: [u8; 32] = encode(&token).keccak256().into();
            let mut rand_val: U256 = U256::from(hash) % balance_sum;
            println!("The initial random value: {:?}", rand_val);
            let mut selected_worker = self.workers[self.workers.len() - 1];
            for i in 0..self.workers.len() {
                let result = rand_val.overflowing_sub(self.balances[i]);
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

