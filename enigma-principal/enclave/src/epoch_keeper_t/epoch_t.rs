use ethabi::{Bytes, encode, Token};
use ethereum_types::{H160, H256, U256};

use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, EnclaveSystemError::*};
use keys_keeper_t::keeper_types_t::{InputWorkerParams, RawEncodable};
use std::string::ToString;

pub type EpochNonce = [u8; 32];

#[derive(Debug, Clone)]
pub struct Epoch {
    pub nonce: U256,
    pub seed: U256,
    pub worker_params: InputWorkerParams,
}

impl Epoch {
    pub fn get_selected_worker(&self, sc_addr: H256) -> Result<H160, EnclaveError> {
        self.worker_params.get_selected_worker(sc_addr, self.seed)?
            .ok_or(SystemError(WorkerAuthError { err: "Worker selection returns nothing.".to_string() }))
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
