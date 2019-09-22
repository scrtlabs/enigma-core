use enigma_tools_m::keeper_types::{InputWorkerParams, RawEncodable};
use ethabi::Bytes;
use ethereum_types::{H160, H256, U256, BigEndianHash};
use std::string::ToString;

use enigma_tools_t::common::errors_t::{
    EnclaveError::{self, SystemError},
    EnclaveSystemError,
};
use enigma_types::ContractAddress;

pub type EpochNonce = [u8; 32];
pub type EpochMarker = [u8; 64];

#[derive(Debug, Clone)]
pub struct Epoch {
    pub nonce: U256,
    pub seed: U256,
    pub worker_params: InputWorkerParams,
}

impl Epoch {
    pub fn get_selected_worker(&self, sc_addr: ContractAddress) -> Result<H160, EnclaveError> {
        self.worker_params
            .get_selected_worker(sc_addr, self.seed)
            .ok_or_else(|| SystemError(EnclaveSystemError::WorkerAuthError { err: "Worker selection returns nothing.".to_string() }))
    }
}

impl RawEncodable for Epoch {
    /// Encode the Epoch as Ethereum ABI parameters
    fn raw_encode(&self) -> Bytes {
        let raw_seed = H256::from_uint(&self.seed).0.to_vec();
        let mut image = raw_seed.len().to_be_bytes().to_vec();
        image.extend(raw_seed);

        let raw_nonce = H256::from_uint(&self.nonce).0.to_vec();
        image.extend(raw_nonce.len().to_be_bytes().to_vec());
        image.extend(raw_nonce);

        image.extend(self.worker_params.workers.len().to_be_bytes().to_vec());
        for addr in self.worker_params.workers.clone() {
            let raw_addr = addr.0.to_vec();
            image.extend(raw_addr.len().to_be_bytes().to_vec());
            image.extend(raw_addr);
        }

        image.extend(self.worker_params.stakes.len().to_be_bytes().to_vec());
        for amount in self.worker_params.stakes.clone() {
            let raw_amount = H256::from_uint(&amount).0.to_vec();
            image.extend(raw_amount.len().to_be_bytes().to_vec());
            image.extend(raw_amount);
        }
        image
    }
}
