use std::collections::HashMap;

use bigint;
use ethabi::{Event, EventParam, ParamType};
use failure::Error;
pub use rlp::{decode, Encodable, encode, RlpStream};
use web3::types::{Address, Bytes, H160, H2048, H256, H64, U256};

use web3_utils::keeper_types_u::InputWorkerParams;

pub trait IntoBigint<T> {
    fn bigint(self) -> T;
}

impl IntoBigint<bigint::H64> for H64 { fn bigint(self) -> bigint::H64 { bigint::H64(self.0) } }

impl IntoBigint<bigint::H160> for H160 { fn bigint(self) -> bigint::H160 { bigint::H160(self.0) } }

impl IntoBigint<bigint::H256> for H256 { fn bigint(self) -> bigint::H256 { bigint::H256(self.0) } }

impl IntoBigint<bigint::U256> for U256 { fn bigint(self) -> bigint::U256 { bigint::U256(self.0) } }

impl IntoBigint<bigint::H2048> for H2048 { fn bigint(self) -> bigint::H2048 { bigint::H2048(self.0) } }

impl IntoBigint<bigint::B256> for Bytes { fn bigint(self) -> bigint::B256 { bigint::B256::new(&self.0) } }

impl Encodable for InputWorkerParams {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.block_number.bigint());
        s.append_list(&self.workers.iter().map(|a| a.bigint()).collect::<Vec<bigint::H160>>());
        s.append_list(&self.stakes.iter().map(|b| b.bigint()).collect::<Vec<bigint::U256>>());
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfirmedEpochState {
    pub selected_workers: HashMap<H256, Address>,
    pub block_number: U256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpochMarker {
    pub seed: U256,
    pub sig: Bytes,
    pub nonce: U256,
    pub confirmed_state: Option<ConfirmedEpochState>,
}

impl EpochMarker {
    pub fn new(seed: U256, sig: Bytes, nonce: U256) -> Self {
        Self { seed, sig, nonce, confirmed_state: None }
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    pub fn confirm(&mut self, worker_params: &InputWorkerParams, sc_addresses: Vec<H256>) -> Result<(), Error> {
        println!("Confimed epoch with worker params: {:?}", worker_params);
        let block_number = worker_params.block_number.clone();
        let mut selected_workers: HashMap<H256, Address> = HashMap::new();
        for sc_address in sc_addresses {
            println!("Getting the selected worker for: {:?}", sc_address);
            match worker_params.get_selected_worker(sc_address.clone(), self.seed.clone())? {
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
}

#[derive(Debug, Clone)]
pub struct WorkersParameterizedEvent(pub Event);

impl WorkersParameterizedEvent {
    pub fn new() -> Self {
        WorkersParameterizedEvent(Event {
            name: "WorkersParameterized".to_string(),
            inputs: vec![EventParam {
                name: "seed".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "firstBlockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "inclusionBlockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "workers".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                indexed: false,
            }, EventParam {
                name: "stakes".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                indexed: false,
            }, EventParam {
                name: "nonce".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }],
            anonymous: false,
        })
    }
}