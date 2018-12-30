// general
use failure::Error;
use sgx_types::sgx_enclave_id_t;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time;
use web3::contract::{CallFuture, Contract, Options};
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::transports::Http;
use web3::types::{Address, H256, U256, FilterBuilder};
use web3::Transport;
use web3::helpers;
use web3::contract::tokens::Tokenizable;
use ethabi::Event;
use ethabi::EventParam;
use ethabi::ParamType;
use ethabi::RawLog;
use ethabi::Log;
use ethabi::Token;

use crate::esgx::random_u;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error>
        where Self: Sized;

    fn set_worker_params<G: Into<U256>>(&self, eid: sgx_enclave_id_t, gas_limit: G) -> CallFuture<H256, <Http as Transport>::Out>;

    fn set_worker_params_internal<G: Into<U256>>(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit: G)
                                  -> CallFuture<H256, <Http as Transport>::Out>;

    fn filter_worker_params(&self);

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
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed: U256 = U256::from_big_endian(&rand_seed);
        println!("[---\u{25B6} seed: {} \u{25C0}---]", the_seed);
        // set gas options for the tx
        let mut options = Options::default();
        options.gas = Some(gas_limit.into());
        // set random seed
        contract.call("setWorkersParams", (the_seed, sig.to_vec()), *account, options)
    }

    fn filter_worker_params(&self) {
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
            .address(vec![self.address()])
            .topics(
                Some(vec![
                    event_sig.into(),
                ]),
                None,
                None,
                None,
            )
            .build();

        let event_future = self.web3.eth_filter()
            .create_logs_filter(filter)
            .then(|filter| {
                filter
                    .unwrap()
                    .stream(time::Duration::from_secs(1))
                    .for_each(|log| {
                        println!("got web3 log: {:?}", log);
                        // ethabi wants the data as a raw Vec so we extract from the Bytes wrapper
                        let rawLog = RawLog { topics: log.topics, data: log.data.0 };
                        let log = match event.parse_log(rawLog) {
                            Ok(log) => log,
                            Err(e) => panic!("unable to parse event log")
                        };
                        let seedToken: Token = log.params[0].value.to_owned();
                        let seed: U256 = Tokenizable::from_token(seedToken).unwrap();

                        let workersToken = log.params[1].value.to_owned();
                        let workers: Vec<Address> = Tokenizable::from_token(workersToken).unwrap();
                        println!("got log: {:?}, seed {:?}, workers {:?}", log, seed, workers);
                        Ok(())
                    })
            })
            .map_err(|_| ());
        event_future.wait().unwrap();
    }


    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, eid: sgx_enclave_id_t, gas_limit: G,
                    max_epochs: Option<usize>) {
        // Make Arcs to support passing the refrence to multiple futures.
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let w3_contract = Arc::new(self.w3_contract.clone());
        let account = Arc::new(self.account);

        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        loop {
            // Clone these arcs to be moved into the future.
            let account = Arc::clone(&account);
            let prev_epoch = Arc::clone(&prev_epoch);
            let w3_contract = Arc::clone(&w3_contract);

            let future = self.web3.eth().block_number().and_then(move |num| {
                let curr_block = num.low_u64() as usize;
                let prev_block_ref = prev_epoch.load(Ordering::Relaxed);
                println!("previous: {}, current block: {}, next: {}", prev_block_ref, curr_block, (prev_block_ref + epoch_size));
//                // Account for the fact that starting the app does not restart the chain
                if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                    prev_epoch.swap(curr_block, Ordering::Relaxed);
                } else if curr_block < prev_block_ref {
                    return Err(web3::Error::from_kind(web3::ErrorKind::InvalidResponse("not the right block".to_string())))
                }
                thread::sleep(time::Duration::from_secs(2));
                println!("[\u{1F50A} ] @ block {}, prev block @ {} [\u{1F50A} ]", curr_block, prev_block_ref);
                Ok(())
            }).map_err(From::from)
                .and_then(move |_| {
                    println!("sending params!");
                    EnigmaContract::set_worker_params_internal(&w3_contract, &account, eid, gas_limit)
                });

            self.eloop.remote().spawn(|_| {
                future.map_err(|err| eprintln!("Errored with: {:?}", err))
                    .map(|res| println!("Res: {:?}", res))
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
