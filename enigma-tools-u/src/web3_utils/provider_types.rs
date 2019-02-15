use bigint;
pub use rlp::{Encodable, encode, decode, RlpStream};
use web3::types::{Block, Bytes, H160, H2048, H256, H64, Log, TransactionReceipt, U256, Address};
use enigma_crypto::hash::Keccak256;
use ethabi::{Event, EventParam, ParamType};

pub trait IntoBigint<T> {
    fn bigint(self) -> T;
}

impl IntoBigint<bigint::H64> for H64 { fn bigint(self) -> bigint::H64 { bigint::H64(self.0) } }

impl IntoBigint<bigint::H160> for H160 { fn bigint(self) -> bigint::H160 { bigint::H160(self.0) } }

impl IntoBigint<bigint::H256> for H256 { fn bigint(self) -> bigint::H256 { bigint::H256(self.0) } }

impl IntoBigint<bigint::U256> for U256 { fn bigint(self) -> bigint::U256 { bigint::U256(self.0) } }

impl IntoBigint<bigint::H2048> for H2048 { fn bigint(self) -> bigint::H2048 { bigint::H2048(self.0) } }

impl IntoBigint<bigint::B256> for Bytes { fn bigint(self) -> bigint::B256 { bigint::B256::new(&self.0) } }

#[derive(Debug, Clone)]
pub struct InputWorkerParams {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub stakes: Vec<U256>,
}
impl Encodable for InputWorkerParams {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.block_number.bigint());
        s.append_list(&self.workers.iter().map(|a| a.bigint()).collect::<Vec<bigint::H160>>());
        s.append_list(&self.stakes.iter().map(|b| b.bigint()).collect::<Vec<bigint::U256>>());
    }
}

#[derive(Debug, Clone)]
pub struct EpochSeed {
    pub seed: U256,
    pub sig: Bytes,
    pub nonce: U256,
}

#[derive(Debug, Clone)]
pub struct EventWrapper(pub Event);

impl EventWrapper {
    pub fn workers_parameterized() -> Self {
        EventWrapper(Event {
            name: "WorkersParameterized".to_string(),
            inputs: vec![EventParam {
                name: "seed".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "blockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "workers".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                indexed: false,
            }, EventParam {
                name: "balances".to_string(),
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
