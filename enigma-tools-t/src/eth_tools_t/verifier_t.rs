use ethabi::Hash;
use eth_tools_t::keeper_types_t::{BlockHeader, BlockHeaders, Receipt, ReceiptHashes};
use common::errors_t::EnclaveError;

struct BlockVerifier {
    pub preverified_hash: Hash,
    pub verified_headers: BlockHeaders,
}

impl BlockVerifier {
    pub fn add_block(&mut self, header: BlockHeader) -> Result<(), EnclaveError> {
        &self.verified_headers.0.push(header);
        Ok(())
    }
}

/// Verify that the current block header links back to the checkpoint block hash
/// through the chain of the provided block headers.
pub fn verify_block_chain(preverified_hash: Hash, headers: BlockHeaders) -> Result<(), EnclaveError> {
    // TODO: Implement, hash each starting from the current until the checkpoint
    Ok(())
}

/// Verify that the provided receipt is included in the receipt_root of the provided block.
pub fn verify_receipt(block: BlockHeader, receipt: Receipt, receipt_hashes: ReceiptHashes) -> Result<(), EnclaveError> {
    Ok(())
}
