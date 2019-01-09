use bigint;
pub use rlp::{Encodable, encode, RlpStream};
use web3::types::{Block, Bytes, H160, H2048, H256, H64, Log, TransactionReceipt, U256};

use common_u::Keccak256;

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
pub struct LogWrapper(pub Log);

impl Encodable for LogWrapper {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.0.address.bigint());
        s.append_list(&self.0.topics.iter().map(|t| t.bigint()).collect::<Vec<bigint::H256>>());
        s.append(&self.0.data.0);
    }
}


#[derive(Debug, Clone)]
pub struct BlockHeaderWrapper(pub Block<H256>);

impl Encodable for BlockHeaderWrapper {
    fn rlp_append(&self, s: &mut RlpStream) {
        //TODO: panic if None?
        let block_number = &self.0.number.unwrap();
        s.begin_list(15);
        s.append(&self.0.parent_hash.bigint());
        s.append(&self.0.uncles_hash.bigint());
        s.append(&self.0.author.bigint());
        s.append(&self.0.state_root.bigint());
        s.append(&self.0.transactions_root.bigint());
        s.append(&self.0.receipts_root.bigint());
        s.append(&self.0.logs_bloom.bigint());
        s.append(&self.0.difficulty.bigint());
        s.append(&U256::from(*block_number).bigint());
        s.append(&self.0.gas_limit.bigint());
        s.append(&self.0.gas_used.bigint());
        s.append(&self.0.timestamp.bigint());
        s.append(&self.0.extra_data.clone().bigint());
        let mix_hash = match &self.0.mix_hash {
            Some(h) => h.bigint(),
            None => H256::from(0).bigint(),
        };
        s.append(&mix_hash);
        let nonce = match &self.0.nonce {
            Some(n) => n.bigint(),
            None => H64::from(0).bigint(),
        };
        s.append(&nonce);
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeadersWrapper(pub Vec<BlockHeaderWrapper>);

impl Encodable for BlockHeadersWrapper {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(1);
        s.append_list(&self.0);
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptWrapper(pub TransactionReceipt);

impl Encodable for ReceiptWrapper {
    fn rlp_append(&self, s: &mut RlpStream) {
        // Supports EIP-658 rules only (blocks after Metropolis)
        let status_code: &u64 = &self.0.status.unwrap().as_u64();
        s.begin_list(4);
        s.append(status_code);
        s.append(&self.0.cumulative_gas_used.bigint());
        s.append(&self.0.logs_bloom.bigint());
        s.append_list(&self.0.logs.iter().map(|l| LogWrapper(l.clone())).collect::<Vec<LogWrapper>>());
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptHashesWrapper(pub Vec<H256>);

impl ReceiptHashesWrapper {
    pub fn from_receipts(receipts: &Vec<ReceiptWrapper>) -> Self {
        let hashes = receipts
            .iter()
            .map(|r| {
                let receipt_rlp = encode(r);
                H256(receipt_rlp.keccak256())
            })
            .collect::<Vec<H256>>();
        ReceiptHashesWrapper(hashes)
    }
}
impl Encodable for ReceiptHashesWrapper {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(1);
        s.append_list(&self.0.iter().map(|h| h.bigint()).collect::<Vec<bigint::H256>>());
    }
}

#[derive(Debug, Clone)]
pub struct EpochSeed {
    pub seed: U256,
    pub sig: Bytes,
    pub nonce: U256,
}
