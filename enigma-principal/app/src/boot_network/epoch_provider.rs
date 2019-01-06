use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time;

use ethabi::Event;
// general
use failure::Error;
use serde_json;
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::{Block, BlockId, FilterBuilder, H256, Log, TransactionReceipt};

use enigma_tools_u::common_u::errors::Web3Error;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::w3utils::connect_batch;
use enigma_tools_u::web3_utils::provider_types::{ReceiptWrapper, ReceiptHashesWrapper, BlockHeaders};
use enigma_tools_u::web3_utils::keeper_types_u::EventWrapper;

use crate::esgx::keymgmt_u;

pub struct EpochProvider {
    contract: Arc<EnigmaContract>,
    last_block_number: Option<AtomicUsize>,
    eid: Arc<AtomicU64>,
}

impl EpochProvider {
    pub fn new(eid: Arc<AtomicU64>, contract: Arc<EnigmaContract>) -> Self {
        EpochProvider { contract, last_block_number: None, eid }
    }

    pub fn filter_worker_params(self: Arc<Self>) {
        let event = EventWrapper::workers_parameterized();
        let event_sig = event.0.signature();
        // Filter for Hello event in our contract
        let filter = FilterBuilder::default()
            .address(vec![self.contract.address()])
            .topics(
                Some(vec![
                    event_sig.into(),
                ]),
                None,
                None,
                None,
            )
            .build();

        let event_future = self.contract.web3.eth_filter()
            .create_logs_filter(filter)
            .then(|filter| {
                filter
                    .unwrap()
                    .stream(time::Duration::from_secs(1))
                    .for_each(|log| {
                        println!("Got WorkerParameterized event log");
                        let em = Arc::clone(&self);
                        thread::spawn(move || {
                            em.store_epoch(log);
                        });
                        Ok(())
                    })
            })
            .map_err(|err| eprintln!("Unable to store worker parameters: {:?}", err));
        event_future.wait().unwrap();
    }

    fn fetch_block(&self, block_hash: H256) -> Result<Block<H256>, Error> {
        let block_id = BlockId::Hash(block_hash);
        let block = match self.contract.web3.eth().block(block_id).wait() {
            Ok(block) => block.unwrap(),
            Err(e) => return Err(Web3Error { message: format!("Unable to fetch block {:?} : {:?}", block_hash, e) }.into()),
        };
//        println!("Got block: {:?}", block);
        Ok(block)
    }

    fn fetch_receipts(&self, transactions: Vec<H256>) -> Result<Vec<TransactionReceipt>, Error> {
        let web3_batch = connect_batch(self.contract.web3.transport().clone());
        for tx in transactions {
//            println!("Fetching receipt for tx: {:?}", tx);
            let _ = web3_batch.eth().transaction_receipt(tx);
        }
//        println!("Submitting the batch request");
        let receipts = web3_batch.transport()
            .submit_batch()
            .map(|results| {
                let mut receipts: Vec<TransactionReceipt> = Vec::new();
                for result in results {
                    let receipt: TransactionReceipt = serde_json::from_value(result.unwrap()).unwrap();
                    receipts.push(receipt);
                }
                receipts
            })
            .wait().unwrap();
        Ok(receipts)
    }

    pub fn store_epoch(&self, log: Log) -> Result<(), Error> {
        let block = self.fetch_block(log.block_hash.unwrap())?;
        let receipts = self.fetch_receipts(block.transactions.clone())?
            .into_iter()
            .map(|r| { ReceiptWrapper { receipt: r, block: block.clone() } })
            .collect::<Vec<ReceiptWrapper>>();
//        println!("Got receipt hashes: {:?}", receipts_hashes);
        // Set the worker parameters in the enclave
        // TODO: enable when all objects are available
//        let sig = keymgmt_u::set_worker_params(self.eid.load(Ordering::SeqCst), log, None, None);
//        println!("Worker parameters stored in Enclave. The signature: {:?}", sig.to_vec());
        Ok(())
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use enigma_tools_u::web3_utils::w3utils;
    use ethabi::{Token, Bytes, RawLog};
    use ethabi;
    use std::env;
    use web3::types::U256;
    use web3::contract::tokens::Tokenizable;
    use enigma_tools_u::web3_utils::provider_types::{encode, LogWrapper, ReceiptWrapper};
    use enigma_tools_u::web3_utils::keeper_types_u::{decode, Log, Receipt, Epoch};

    /// This function is important to enable testing both on the CI server and local.
    /// On the CI Side:
    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
    /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:9545")) }

    #[test]
    fn test_mock_receipt() {
        let event = EventWrapper::workers_parameterized();
        let url = get_node_url();
        println!("Connection to Ethereum node: {:?}", url);
        let (_eloop, web3) = w3utils::connect(&url).unwrap();
        println!("Got web3");

        let tx = serde_json::from_str::<H256>("\"0x33c3c14e3cd8764911d243e67c229adf7279b3e920a3dbb317ff989946ad47bb\"").unwrap();
        println!("Fetching Receipt for: {:?}", tx);
        let receipt = web3.eth().transaction_receipt(tx).wait().unwrap().unwrap();

        let block_id = BlockId::Hash(receipt.clone().block_hash.unwrap());
        let block = web3.eth().block(block_id).wait().unwrap().unwrap();

        let receipt_wrapper = ReceiptWrapper { receipt: receipt.clone(), block };
        let receipt_bytes = encode(&receipt_wrapper);
        println!("The receipt RLP bytes: {:?}", receipt_bytes);

        let decoded_receipt: Receipt = decode(&receipt_bytes);
        println!("The receipt: {:?}", decoded_receipt);

        let log = LogWrapper(receipt.clone().logs[0].clone());
        let tokens: Vec<Token> = log.clone().into();
        println!("The log ABI tokens: {:?}", ethabi::encode(&tokens));

        let bytes = encode(&log);
        println!("The log RLP bytes: {:?}", bytes);

        let decoded_log: Log = decode(&bytes);
        println!("The receipt raw log: {:?}", decoded_log);
    }
}
