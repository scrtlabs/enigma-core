use ethabi::{Bytes, encode, Hash, Token};
use ethereum_types::{H160, H256, U256};
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use keys_keeper_t::keeper_types_t::{InputWorkerParams, RawEncodable};

pub type EpochNonce = [u8; 32];

pub trait IntoBigint<T> {
    fn bigint(self) -> T;
}

#[derive(Debug, Clone)]
pub struct Epoch {
    pub nonce: U256,
    pub seed: U256,
    pub worker_params: InputWorkerParams,
}

impl Epoch {
    pub fn get_selected_worker(&self, sc_addr: H256) -> Result<H160, EnclaveError> {
        let worker = match self.worker_params.get_selected_worker(sc_addr, self.seed)? {
            Some(worker) => worker,
            None => {
                return Err(EnclaveError::WorkerAuthError {
                    err: format!("Worker selection return nothing.")
                });
            }
        };
        Ok(worker)
    }
}

impl RawEncodable for Epoch {
    /// Encode the Epoch as Ethereum ABI parameters
    fn raw_encode(&self) -> Result<Bytes, EnclaveError> {
        let tokens = vec![
            Token::Uint(self.seed),
            Token::Uint(self.nonce),
            Token::Array(self.worker_params.workers.iter().map(|a| Token::Address(*a)).collect()),
            Token::Array(self.worker_params.stakes.iter().map(|s| Token::Uint(*s)).collect()),
        ];
        Ok(encode(&tokens))
    }
}
