// general
use failure::Error;
use sgx_types::sgx_enclave_id_t;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time;
use web3::contract::{CallFuture, Contract, Options};
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::transports::Http;
use web3::types::{Address, H256, U256, FilterBuilder, BlockId, BlockHeader, Log};
use web3::Transport;
use web3::helpers;
use web3::contract::tokens::Tokenizable;
use ethabi::Event;
use ethabi::EventParam;
use ethabi::ParamType;
use ethabi::RawLog;
use ethabi::Token;

use crate::esgx::keymgmt_u;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::w3utils::connect_batch;
use web3::BatchTransport;
use web3::types::TransactionReceipt;
use web3::Web3;
use web3::transports::Batch;
use web3::transports::EventLoopHandle;

const ACTIVE_EPOCH_CODE: &str = "ACTIVE_EPOCH";


// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error>
        where Self: Sized;

    fn set_worker_params<G: Into<U256>>(&self, eid: sgx_enclave_id_t, gas_limit: G) -> CallFuture<H256, <Http as Transport>::Out>;

    fn set_worker_params_internal<G: Into<U256>>(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit: G)
                                                 -> CallFuture<H256, <Http as Transport>::Out>;

    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, eid: sgx_enclave_id_t, gas_limit: G,
                                   max_epochs: Option<usize>);
}

impl Principal for EnigmaContract {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> {
        Ok(Self::from_deployed(address, path, Some(account), url)?)
    }

    // set (seed,signature(seed)) into the enigma smart contract
    fn set_worker_params<G: Into<U256>>(&self, eid: sgx_enclave_id_t, gas_limit: G) -> CallFuture<H256, <Http as Transport>::Out> {
        Self::set_worker_params_internal(&self.w3_contract, &self.account, eid, gas_limit)
    }

    fn set_worker_params_internal<G: Into<U256>>(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit: G)
                                                 -> CallFuture<H256, <Http as Transport>::Out> {
        // get seed,signature
        let (rand_seed, sig) = keymgmt_u::generate_epoch_seed(eid);
        let the_seed: U256 = U256::from_big_endian(&rand_seed);
        println!("[---\u{25B6} seed: {} \u{25C0}---]", the_seed);
        // set gas options for the tx
        let mut options = Options::default();
        options.gas = Some(gas_limit.into());
        // set random seed
        contract.call("setWorkersParams", (the_seed, sig.to_vec()), account.clone(), options)
    }


    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, eid: sgx_enclave_id_t, gas_limit: G,
                                   max_epochs: Option<usize>) {
        // Make Arcs to support passing the refrence to multiple futures.
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let w3_contract = Arc::new(self.w3_contract.clone());
        let account = Arc::new(self.account.clone());

        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        // TODO: Consider subscribing to block header instead of a loop like this: https://github.com/tomusdrw/rust-web3/blob/52cb309c951467625c201a9274ba0d7d739ebb3c/src/api/eth_subscribe.rs
        loop {
            // Clone these arcs to be moved into the future.
            let account = Arc::clone(&account);
            let prev_epoch = Arc::clone(&prev_epoch);
            let w3_contract = Arc::clone(&w3_contract);

            let future = self.web3.eth().block_number().and_then(move |num| {
                let curr_block = num.low_u64() as usize;
                let prev_block_ref = prev_epoch.load(Ordering::Relaxed);
                println!("[\u{1F50A} ] Blocks @ previous: {}, current: {}, next: {} [\u{1F50A} ]", prev_block_ref, curr_block, (prev_block_ref + epoch_size));
//                // Account for the fact that starting the app does not restart the chain
                if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                    prev_epoch.swap(curr_block, Ordering::Relaxed);
                    return Ok(());
                }
                // Continue the loop
                Err(web3::Error::from_kind(web3::ErrorKind::InvalidResponse(ACTIVE_EPOCH_CODE.to_string())))
            }).map_err(From::from)
                .and_then(move |_| {
                    println!("sending params!");
                    EnigmaContract::set_worker_params_internal(&w3_contract, &account, eid, gas_limit)
                });

            self.eloop.remote().spawn(|_| {
                future.map_err(|err| {
                    //TODO: Is there a cleaner way to break the Future chain?
                    if err.to_string().ends_with(&ACTIVE_EPOCH_CODE) {
                        println!("Epoch still active");
                    } else {
                        eprintln!("Errored with: {:?}", err)
                    }
                })
                    .map(|res| println!("The setWorkersParams tx: {:?}", res))
            });
            thread::sleep(time::Duration::from_secs(polling_interval));
            epoch_counter += 1;
            if max_epochs != 0 && epoch_counter == max_epochs {
                println!("[+] Principal: reached max_epochs {} , stopping.", max_epochs);
                break;
            }
        }
    }
}

pub struct EpochMgmt {
    pub contract: Arc<EnigmaContract>,
    eid: AtomicU64,
}

impl EpochMgmt {
    pub fn new(eid: AtomicU64, contract: Arc<EnigmaContract>) -> Result<Self, Error> {
        Ok(EpochMgmt { contract, eid })
    }

    pub fn store_epoch(&self, log: Log) {
        // Set the worker parameters in the enclave
        // TODO: Make sure that errors are caught properly
//                        let web3 = connect_batch(self.web3.transport().clone());
//                        println!("Fetching block: {:?}", block_id);
//                        // TODO: Use web3 Batch requests instead. I had difficulty creating a Batch transport that works with the same eloop.
        let block_id = BlockId::Hash(log.block_hash.unwrap());
        let future = self.contract.web3.eth().block(block_id).then(move |res| {
            let block = res.unwrap().unwrap();
            println!("Got block: {:?}", block);
            for tx in block.transactions {
//                let receipt = self.web3.eth().transaction_receipt(tx).then(move |res| {
//                    println!("Got receipt for {:?}", tx);
//                    Ok(())
//                }).map_err(|err: Error| eprintln!("{:?}", err));
//                    self.eloop.remote().spawn(|_| receipt);
            }
            Ok(())
        }).map_err(|err: Error| eprintln!("{:?}", err));
////                            .and_then(move |block| {
////                                let mut future: Option<CallFuture<Option<TransactionReceipt>, Transport::Out>> = None;
////                                for tx in block.transactions {
////                                    let _  = web3.eth().transaction_receipt(tx);
//////                                    future = match future {
//////                                        Some(f) => f.join(req),
//////                                        None => req,
//////                                    }
////                                }
////                                future.unwrap()
////                            });
        self.contract.eloop.remote().spawn(|_| future);
        let sig = keymgmt_u::set_worker_params(self.eid.load(Ordering::SeqCst), log, None, None);
        println!("Worker parameters stored in Enclave. The signature: {:?}", sig.to_vec());
    }

    pub fn filter_worker_params(&self) {
        let event = Event {
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
        };
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
                        self.store_epoch(log);
                        Ok(())
                    })
            })
            .map_err(|err| eprintln!("Unable to store worker parameters: {:?}", err));
        event_future.wait().unwrap();
    }
}
