use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time;

use ethabi::Event;
use ethabi::EventParam;
use ethabi::ParamType;
// general
use failure::Error;
use serde_json;
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::{Block, BlockId, FilterBuilder, H256, Log, TransactionReceipt};

use common_u::trie_wrapper::ReceiptWrapper;
use enigma_tools_u::common_u::errors::Web3Error;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::w3utils::connect_batch;

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

    pub fn get_workers_parameterized_event() -> Event {
        Event {
            name: "WorkersParameterized".to_owned(),
            inputs: vec![EventParam {
                name: "seed".to_owned(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "workers".to_owned(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                indexed: false,
            }, EventParam {
                name: "_success".to_owned(),
                kind: ParamType::Bool,
                indexed: false,
            }],
            anonymous: false,
        }
    }

    pub fn filter_worker_params(self: Arc<Self>) {
        let event = EpochProvider::get_workers_parameterized_event();
        let event_sig = event.signature();
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
        let receipts_hashes: Vec<H256> = self.fetch_receipts(block.transactions.clone())?
            .into_iter()
            .map(|r| -> H256 { r.leaf_hash(block.clone()) })
            .collect();
//        println!("Got receipt hashes: {:?}", receipts_hashes);
        // Set the worker parameters in the enclave
        let sig = keymgmt_u::set_worker_params(self.eid.load(Ordering::SeqCst), log, None, None);
//        println!("Worker parameters stored in Enclave. The signature: {:?}", sig.to_vec());
        Ok(())
    }
}
