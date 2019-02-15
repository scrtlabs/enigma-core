pub use rlp::{Decodable, DecoderError, decode, UntrustedRlp};
use ethabi::{Address};
use ethereum_types::{H256, H160, U256, H64};
use std::vec::Vec;
use bigint;
use bigint::{H2048};

pub trait FromBigint<T>: Sized {
    fn from_bigint(_: T) -> Self;
}

impl FromBigint<bigint::H64> for H64 { fn from_bigint(b: bigint::H64) -> Self { H64(b.0) } }

impl FromBigint<bigint::H256> for H256 { fn from_bigint(b: bigint::H256) -> Self { H256(b.0) } }

impl FromBigint<bigint::H160> for H160 { fn from_bigint(b: bigint::H160) -> Self { H160(b.0) } }

impl FromBigint<bigint::U256> for U256 { fn from_bigint(b: bigint::U256) -> Self { U256(b.0) } }

impl FromBigint<bigint::H2048> for H2048 { fn from_bigint(b: bigint::H2048) -> Self { H2048(b.0) } }

#[derive(Debug, Clone)]
pub struct InputWorkerParams {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub stakes: Vec<U256>,
}

impl Decodable for InputWorkerParams {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            block_number: U256::from_bigint(rlp.val_at(0)?),
            workers: rlp.list_at(1)?.iter().map(|a| H160::from_bigint(*a)).collect::<Vec<H160>>(),
            stakes: rlp.list_at(2)?.iter().map(|b| U256::from_bigint(*b)).collect::<Vec<U256>>(),
        })
    }
}
