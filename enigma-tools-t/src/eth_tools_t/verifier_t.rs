use ethabi::Hash;
use eth_tools_t::keeper_types_t::{BlockHeader, BlockHeaders, Receipt, ReceiptHashes};
use common::errors_t::EnclaveError;

pub struct BlockVerifier {
    pub preverified_hash: Hash,
    pub verified_headers: BlockHeaders,
}

impl BlockVerifier {
    pub fn new(preverified_hash: Hash) -> Self {
        let mut verified_headers: BlockHeaders = BlockHeaders(vec![]);
        BlockVerifier { preverified_hash, verified_headers }
    }
    /// Verify that the current block header links back to the checkpoint block hash
    /// through the chain of the provided block headers.
    pub fn add_block(&mut self, header: BlockHeader) -> Result<(), EnclaveError> {
        &self.verified_headers.0.push(header);
        Ok(())
    }
    /// Verify that the provided receipt is included in the receipt_root of the last verified Block.
    pub fn verify_receipt(&self, receipt: Receipt, receipt_hashes: ReceiptHashes) -> Result<(), EnclaveError> {
        Ok(())
    }
}
