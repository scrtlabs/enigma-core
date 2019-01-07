pub use rlp::{Decodable, DecoderError, decode, UntrustedRlp};
use ethabi::{Token, Bytes, RawLog, Event, EventParam, ParamType, Hash, Address};
use ethereum_types::{H256, H160, U256, H64, U64};
use ethabi::token::Tokenizer;
use ethabi::token::LenientTokenizer;
use std::vec::Vec;
use std::string::ToString;
use std::prelude::v1::Box;
use bigint;
use bigint::{H2048, B256};

pub trait FromBigint<T>: Sized {
    fn from_bigint(_: T) -> Self;
}

impl FromBigint<bigint::H64> for H64 { fn from_bigint(b: bigint::H64) -> Self { H64(b.0) } }

impl FromBigint<bigint::H256> for H256 { fn from_bigint(b: bigint::H256) -> Self { H256(b.0) } }

impl FromBigint<bigint::H160> for H160 { fn from_bigint(b: bigint::H160) -> Self { H160(b.0) } }

impl FromBigint<bigint::U256> for U256 { fn from_bigint(b: bigint::U256) -> Self { U256(b.0) } }

impl FromBigint<bigint::H2048> for H2048 { fn from_bigint(b: bigint::H2048) -> Self { H2048(b.0) } }

#[derive(Debug, Clone)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl Decodable for Log {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            address: H160::from_bigint(rlp.val_at(0)?),
            topics: rlp.list_at(1)?.iter().map(|t| H256::from_bigint(*t)).collect::<Vec<H256>>(),
            data: rlp.val_at(2)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub status: U64,
    pub cumulative_gas_used: U256,
    pub logs_bloom: H2048,
    pub logs: Vec<Log>,
}

impl Decodable for Receipt {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        // Supports EIP-658 rules only (blocks after Metropolis)
        let status_code: u64 = rlp.val_at(0)?;
        Ok(Self {
            status: U64::from(status_code),
            cumulative_gas_used: U256::from_bigint(rlp.val_at(1)?),
            logs_bloom: rlp.val_at(2)?,
            logs: rlp.list_at(3)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptHashes(pub Vec<H256>);

impl Decodable for ReceiptHashes {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(ReceiptHashes(rlp.list_at(0)?.iter().map(|h| H256::from_bigint(*h)).collect::<Vec<H256>>()))
    }
}

#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub uncles_hash: H256,
    pub author: H160,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: H2048,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: U256,
    pub extra_data: B256,
    pub mix_hash: H256,
    pub nonce: H64,
}

impl Decodable for BlockHeader {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            parent_hash: H256::from_bigint(rlp.val_at(0)?),
            uncles_hash: H256::from_bigint(rlp.val_at(1)?),
            author: H160::from_bigint(rlp.val_at(2)?),
            state_root: H256::from_bigint(rlp.val_at(3)?),
            transactions_root: H256::from_bigint(rlp.val_at(4)?),
            receipts_root: H256::from_bigint(rlp.val_at(5)?),
            logs_bloom: H2048::from_bigint(rlp.val_at(6)?),
            difficulty: U256::from_bigint(rlp.val_at(7)?),
            number: U256::from_bigint(rlp.val_at(8)?),
            gas_limit: U256::from_bigint(rlp.val_at(9)?),
            gas_used: U256::from_bigint(rlp.val_at(10)?),
            timestamp: U256::from_bigint(rlp.val_at(11)?),
            extra_data: rlp.val_at(12)?,
            mix_hash: H256::from_bigint(rlp.val_at(13)?),
            nonce: H64::from_bigint(rlp.val_at(14)?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeaders(pub Vec<BlockHeader>);

impl Decodable for BlockHeaders {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(BlockHeaders(rlp.list_at(0)?))
    }
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

