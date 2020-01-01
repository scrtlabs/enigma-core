use std::collections::HashMap;
use rustc_hex::ToHex;

use enigma_tools_m::keeper_types::InputWorkerParams;
use ethabi::{Event, EventParam, ParamType};
use failure::Error;
pub use rlp::{decode, Encodable, encode, RlpStream};
use serde::{Deserialize, Serialize};
use web3::types::{Address, Bytes, H160, U256};

use enigma_types::ContractAddress;
use enigma_types::Hash256;
use common_u::errors::EpochStateTransitionErr;

pub const EPOCH_STATE_UNCONFIRMED: &str = "UNCONFIRMED";
pub const WORKER_PARAMETERIZED_EVENT: &str = "WorkersParameterized";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedEpochState {
    pub selected_workers: HashMap<Hash256, H160>,
    /// The ether_block_number is the block_number which we conclude from the actual start of the epoch
    /// (it may differ from km_block_number due to latency issues in the network)
    pub ether_block_number: U256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpochState {
    pub seed: U256,
    pub sig: Bytes,
    pub nonce: U256,
    /// The km_block_number is the block in which the KM decided to start a new epoch and
    /// the active workers are concluded from for the epoch
    /// (It might differ from the ether_block_number due to latency in networks)
    pub km_block_number: U256,
    pub confirmed_state: Option<ConfirmedEpochState>,
}

impl EpochState {
    pub fn new(seed: U256, sig: Bytes, nonce: U256, km_block_number: U256) -> Self {
        Self { seed, sig, nonce, km_block_number, confirmed_state: None }
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    ///
    /// # Arguments
    ///
    /// * `worker_params` - The `InputWorkerParams` used to run the worker selection algorithm
    /// * `sc_addresses` - The Secret Contract addresses for which to retrieve the selected worker
    #[logfn(DEBUG)]
    pub fn confirm(
        &mut self, ether_block_number: U256, worker_params: &InputWorkerParams, sc_addresses: Vec<ContractAddress>,
    ) -> Result<(), Error> {
        info!("Confirmed epoch with worker params: {:?}", worker_params);
        let mut selected_workers: HashMap<ContractAddress, Address> = HashMap::new();
        for sc_address in sc_addresses {
            match worker_params.get_selected_worker(sc_address, self.seed) {
                Some(worker) => {
                    trace!("Found selected worker: {:?} for contract: {:?}", worker, sc_address.to_hex());
                    match selected_workers.insert(sc_address, worker) {
                        Some(prev) => trace!("Selected worker inserted after: {:?}", prev),
                        None => trace!("First selected worker inserted"),
                    }
                }
                None => {
                    trace!("Selected worker not found for contract: {:?}", sc_address.to_hex());
                }
            }
        }
        self.confirmed_state = Some(ConfirmedEpochState { selected_workers, ether_block_number });
        Ok(())
    }

    /// Returns the contract address that the worker is selected to work on during this epoch
    ///
    /// # Arguments
    ///
    /// * `worker` - The worker signing address
    #[logfn(DEBUG)]
    pub fn get_contract_addresses(&self, worker: &H160) -> Result<Vec<ContractAddress>, Error> {
        let addrs = match &self.confirmed_state {
            Some(state) => {
                let mut addrs: Vec<ContractAddress> = Vec::new();
                for (&addr, account) in &state.selected_workers {
                    if account == worker {
                        addrs.push(addr);
                    }
                }
                addrs
            }
            None => return Err(EpochStateTransitionErr { current_state: EPOCH_STATE_UNCONFIRMED.to_string() }.into()),
        };
        Ok(addrs)
    }
}

#[derive(Debug, Clone)]
pub struct WorkersParameterizedEvent(pub Event);

impl WorkersParameterizedEvent {
    pub fn new() -> Self {
        WorkersParameterizedEvent(Event {
            name: WORKER_PARAMETERIZED_EVENT.to_string(),
            inputs: vec![
                EventParam { name: "seed".to_string(), kind: ParamType::Uint(256), indexed: false },
                EventParam { name: "firstBlockNumber".to_string(), kind: ParamType::Uint(256), indexed: false },
                EventParam { name: "inclusionBlockNumber".to_string(), kind: ParamType::Uint(256), indexed: false },
                EventParam { name: "workers".to_string(), kind: ParamType::Array(Box::new(ParamType::Address)), indexed: false },
                EventParam { name: "stakes".to_string(), kind: ParamType::Array(Box::new(ParamType::Uint(256))), indexed: false },
                EventParam { name: "nonce".to_string(), kind: ParamType::Uint(256), indexed: false },
            ],
            anonymous: false,
        })
    }
}
