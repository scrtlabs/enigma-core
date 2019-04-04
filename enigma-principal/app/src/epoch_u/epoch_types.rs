use enigma_tools_m::keeper_types::InputWorkerParams;
use enigma_types::ContractAddress;
use ethabi::{Event, EventParam, ParamType};
use failure::Error;
pub use rlp::{decode, encode, Encodable, RlpStream};
use std::collections::HashMap;
use web3::types::{Address, Bytes, H160, U256};
use enigma_types::Hash256;
use serde::{Serializer, Deserializer, Serialize, Deserialize};
use serde::ser::SerializeMap;
use rustc_hex::ToHex;

mod selected_workers {
    use super::*;

    pub fn serialize<S>(workers: &HashMap<Hash256, H160>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut workers_map = serializer.serialize_map(Some(workers.len()))?;
        for (k, v) in workers {
            workers_map.serialize_entry(&k.to_hex(), &v)?;
        }
        workers_map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Hash256, H160>, D::Error>
        where
            D: Deserializer<'de>,
    {
        use serde::de::Error;
        let m = HashMap::<String, H160>::deserialize(deserializer)?;
        let mut workers_map = HashMap::<Hash256, H160>::new();
        for (k, v) in &m {
            workers_map.insert(Hash256::from_hex(&k).map_err(Error::custom)?, *v);
        }
        Ok(workers_map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedEpochState {
    #[serde(with = "selected_workers")]
    pub selected_workers: HashMap<Hash256, H160>,
    pub block_number: U256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpochState {
    pub seed: U256,
    pub sig: Bytes,
    pub nonce: U256,
    pub confirmed_state: Option<ConfirmedEpochState>,
}

impl EpochState {
    pub fn new(seed: U256, sig: Bytes, nonce: U256) -> Self { Self { seed, sig, nonce, confirmed_state: None } }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    ///
    /// # Arguments
    ///
    /// * `worker_params` - The `InputWorkerParams` used to run the worker selection algorithm
    /// * `sc_addresses` - The Secret Contract addresses for which to retrieve the selected worker
    #[logfn(DEBUG)]
    pub fn confirm(
        &mut self, block_number: U256, worker_params: &InputWorkerParams, sc_addresses: Vec<ContractAddress>,
    ) -> Result<(), Error> {
        println!("Confirmed epoch with worker params: {:?}", worker_params);
        let mut selected_workers: HashMap<ContractAddress, Address> = HashMap::new();
        for sc_address in sc_addresses {
            println!("Getting the selected worker for: {:?}", sc_address);
            match worker_params.get_selected_worker(sc_address, self.seed) {
                Some(worker) => {
                    println!("Found selected worker: {:?} for contract: {:?}", worker, sc_address);
                    match selected_workers.insert(sc_address, worker) {
                        Some(prev) => println!("Selected worker inserted after: {:?}", prev),
                        None => println!("First selected worker inserted"),
                    }
                }
                None => {
                    println!("Selected worker not found for contract: {:?}", sc_address);
                }
            }
        }
        self.confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });
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
            None => bail!("Cannot get contract addresses until the EpochState is confirmed."),
        };
        Ok(addrs)
    }
}

#[derive(Debug, Clone)]
pub struct WorkersParameterizedEvent(pub Event);

impl WorkersParameterizedEvent {
    pub fn new() -> Self {
        WorkersParameterizedEvent(Event {
            name: "WorkersParameterized".to_string(),
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
