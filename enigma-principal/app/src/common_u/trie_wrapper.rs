use rlp;
use block::Log;
use block::{Receipt, Header};
use bigint;
use bloom::LogsBloom;
use web3::types::{TransactionReceipt, Block, H256, H160, U256, H2048, U128, Bytes, H64};
use rlp::Encodable;
use rustc_hex::ToHex;
use block::HeaderHash;


pub trait BigIntWrapper<T> {
    fn bigint(self) -> T;
}

impl BigIntWrapper<bigint::H64> for H64 { fn bigint(self) -> bigint::H64 { bigint::H64(self.0) } }

impl BigIntWrapper<bigint::H160> for H160 { fn bigint(self) -> bigint::H160 { bigint::H160(self.0) } }

impl BigIntWrapper<bigint::H256> for H256 { fn bigint(self) -> bigint::H256 { bigint::H256(self.0) } }

impl BigIntWrapper<bigint::U256> for U256 { fn bigint(self) -> bigint::U256 { bigint::U256(self.0) } }

impl BigIntWrapper<bigint::U128> for U128 { fn bigint(self) -> bigint::U128 { bigint::U128(self.0) } }

impl BigIntWrapper<bigint::Gas> for U256 { fn bigint(self) -> bigint::Gas { bigint::Gas::from(bigint::U256(self.0)) } }

impl BigIntWrapper<u64> for U256 { fn bigint(self) -> u64 { self.as_u64() } }

impl BigIntWrapper<LogsBloom> for H2048 { fn bigint(self) -> LogsBloom { LogsBloom::from(bigint::H2048(self.0)) } }

impl BigIntWrapper<bigint::B256> for Bytes { fn bigint(self) -> bigint::B256 { bigint::B256::new(&self.0) } }


pub trait ReceiptWrapper {
    type Hash;
    type Leaf;
    fn leaf(&self, block: Block<H256>) -> Self::Leaf;
    fn leaf_hash(&self, block: Block<H256>) -> Self::Hash;
}

impl ReceiptWrapper for TransactionReceipt {
    type Hash = H256;
    type Leaf = Receipt;
    fn leaf(&self, block: Block<H256>) -> Self::Leaf {
        Receipt {
            state_root: block.state_root.bigint(),
            used_gas: self.gas_used.bigint(),
            logs_bloom: block.logs_bloom.bigint(),
            logs: self.logs.clone()
                .into_iter()
                .map(|l| {
                    Log {
                        address: l.address.bigint(),
                        topics: l.topics.into_iter().map(|t| t.bigint()).collect(),
                        data: l.data.0,
                    }
                })
                .collect(),
        }
    }
    fn leaf_hash(&self, block: Block<H256>) -> Self::Hash {
        println!("Hashing transaction receipt: {:?} with block: {:?}", self, block);
        let receipt: Receipt = self.leaf(block.clone());
        println!("The receipt bytes: {}", receipt.rlp_bytes().to_hex());
        let receipts = vec![receipt];
        let receipt_root = block::receipts_root(&receipts);
        println!("Got receipt root: {:?}", receipt_root);
        H256::from(0)
    }
}

pub trait HeaderWrapper {
    type Hash;
    type Leaf;
    fn leaf(&self) -> Self::Leaf;
    fn leaf_hash(&self) -> Self::Hash;
}

impl HeaderWrapper for Block<H256> {
    type Hash = H256;
    type Leaf = Header;
    fn leaf(&self) -> Self::Leaf {
        Header {
            parent_hash: self.parent_hash.bigint(),
            ommers_hash: self.uncles_hash.bigint(),
            beneficiary: self.author.bigint(),
            state_root: self.state_root.bigint(),
            transactions_root: self.transactions_root.bigint(),
            receipts_root: self.receipts_root.bigint(),
            logs_bloom: self.logs_bloom.bigint(),
            difficulty: self.difficulty.bigint(),
            number: bigint::U256::from(self.number.unwrap().bigint()),
            gas_limit: self.gas_limit.bigint(),
            gas_used: self.gas_used.bigint(),
            timestamp: self.timestamp.bigint(),
            extra_data: self.extra_data.clone().bigint(),
            mix_hash: bigint::H256::from(0), // TODO: missing from web3
            nonce: bigint::H64::from(bigint::H256::from(0)), // TODO: missing from web3
        }
    }
    fn leaf_hash(&self) -> Self::Hash {
        println!("Hashing transaction tx: {:?}", self);
        let block_header: Header = self.leaf();
        println!("The header hash: {}", block_header.header_hash());
        H256::from(0)
    }
}

