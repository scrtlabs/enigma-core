use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::mem;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time;

use ethabi::{Event, Log, ParseLog, RawLog};
use failure::Error;
use serde_json;
// general
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::{Address, FilterBuilder, H256, TransactionReceipt, U256};

use enigma_tools_u::web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract};
use enigma_tools_u::web3_utils::keeper_types_u::InputWorkerParams;
use enigma_tools_u::web3_utils::provider_types::{ConfirmedEpochState, EpochMarker, WorkersParameterizedEvent};
use esgx::epoch_keeper_u::set_worker_params;
use esgx::general::{ENCLAVE_DIR, storage_dir};
use boot_network::principal_manager::PrincipalConfig;

pub struct EpochProvider {
    pub contract: Arc<EnigmaContract>,
    pub epoch_marker: Arc<Mutex<Option<EpochMarker>>>,
    pub eid: Arc<AtomicU64>,
}

impl EpochProvider {
    pub fn new(eid: Arc<AtomicU64>, contract: Arc<EnigmaContract>) -> Result<EpochProvider, Error> {
        let epoch_marker_val = Self::read_epoch_marker()?;
        println!("Initializing EpochProvider with EpochMarker: {:?}", epoch_marker_val);
        let epoch_marker = Arc::new(Mutex::new(epoch_marker_val));
        Ok(Self { contract, epoch_marker, eid })
    }

    fn get_marker_file_path() -> PathBuf {
        let mut path = storage_dir();
        path.join(ENCLAVE_DIR);
        path.push("epoch-marker.json");
        path
    }

    pub fn reset_epoch_marker(&self) -> Result<(), Error> {
        self.set_epoch_marker(None)?;
        Ok(())
    }

    fn read_epoch_marker() -> Result<Option<EpochMarker>, Error> {
        let epoch_marker = match File::open(Self::get_marker_file_path()) {
            Ok(mut f) => {
                let mut data = String::new();
                f.read_to_string(&mut data)?;
                let epoch_marker: Option<EpochMarker> = match serde_json::from_str(&data) {
                    Ok(value) => Some(value),
                    Err(err) => {
                        eprintln!("Unable to read block marker file: {:?}", err);
                        None
                    }
                };
                epoch_marker
            }
            Err(_) => {
                println!("No existing epoch marker, starting with block 0");
                None
            }
        };
        Ok(epoch_marker)
    }

    fn write_epoch_marker(epoch_marker: Option<EpochMarker>) -> Result<(), Error> {
        let path = Self::get_marker_file_path();
        if epoch_marker.is_some() {
            let mut file = File::create(path)?;
            let contents = serde_json::to_string(&epoch_marker.unwrap())?;
            file.write_all(contents.as_bytes())?;
        } else {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn parse_worker_parameterized(&self, receipt: &TransactionReceipt) -> Result<(Log), Error> {
        let log = receipt.logs[0].clone();
        let raw_log = RawLog { topics: log.topics, data: log.data.0 };
        let event = WorkersParameterizedEvent::new();
        let result = match event.0.parse_log(raw_log) {
            Ok(result) => result,
            Err(_) => bail!("Unable to parse WorkersParameterized"),
        };
        println!("Parsed the WorkerParameterized event: {:?}", result);
        Ok(result)
    }

    pub fn get_marker(&self) -> Result<EpochMarker, Error> {
        let guard = match self.epoch_marker.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex."),
        };
        let epoch_marker = match guard.deref() {
            Some(epoch_marker) => epoch_marker.clone(),
            None => bail!("Epoch Marker not set."),
        };
        mem::drop(guard);
        Ok(epoch_marker)
    }

    fn set_epoch_marker(&self, epoch_marker: Option<EpochMarker>) -> Result<(), Error> {
        println!("Replacing EpochMaker mutex: {:?}", epoch_marker);
        let mut guard = match self.epoch_marker.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex"),
        };
        let prev = mem::replace(&mut *guard, epoch_marker.clone());
        println!("Replaced EpochMaker: {:?} with: {:?}", prev, epoch_marker);
        mem::drop(guard);
        match Self::write_epoch_marker(epoch_marker) {
            Ok(_) => println!("Stored the Epoch Marker to disk"),
            Err(err) => bail!(err),
        };
        Ok(())
    }

    pub fn get_confirmed(&self) -> Result<ConfirmedEpochState, Error> {
        let guard = match self.epoch_marker.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex."),
        };
        let confirmed_state = match guard.deref() {
            Some(epoch_marker) => match &epoch_marker.confirmed_state {
                Some(confirmed_state) => confirmed_state.clone(),
                None => bail!("Epoch Marker not confirmed yet."),
            },
            None => bail!("Unable to get seed without an Epoch Marker."),
        };
        mem::drop(guard);
        Ok(confirmed_state)
    }

    /// Seal the epoch data in the enclave, get a random seed and submit to the Enigma contract
    /// The enclave signs on:
    ///  - The worker parameters active at the specified block number
    ///  - The random seed generated by the enclave
    ///  - The sealed nonce incremented for each random seed generated
    /// The Enigma contract verifies the signature. It will revert if:
    ///  - The nonce incremented by the contract does not match the nonce incremented by the enclave
    ///    this prevents the Principal node operator from updating the seed without publishing
    ///    a transaction.
    ///  - The list of active worker parameters does not match the sealed epoch data. This prevents
    ///    the enclave operator from tempering with worker parameters in order to modify the
    ///    result of the worker selection.
    pub fn set_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize) -> Result<(H256), Error> {
        let worker_params: InputWorkerParams = self.contract.get_active_workers(block_number)?;
        println!("The active workers: {:?}", worker_params);
        let epoch_marker = &mut set_worker_params(self.eid.load(Ordering::SeqCst), worker_params.clone())?;
        println!("Waiting for setWorkerParams({:?}, {:?}, {:?})", block_number, epoch_marker.seed, epoch_marker.sig);
        // TODO: Consider a retry mechanism, either store the EpochSeed or add a getter ecall
        let receipt = self.contract.set_workers_params(block_number, epoch_marker.seed.clone(), epoch_marker.sig.clone(), gas_limit, confirmations)?;
        self.parse_worker_parameterized(&receipt)?;
        println!("Caching selected workers");
        self.confirm_epoch(epoch_marker, worker_params)?;
        println!("Got the receipt: {:?}", receipt);
        self.set_epoch_marker(Some(epoch_marker.clone()));
        Ok(receipt.transaction_hash)
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    pub fn confirm_epoch(&self, epoch_marker: &mut EpochMarker, worker_params: InputWorkerParams) -> Result<(), Error> {
        let contract_count = self.contract.count_secret_contracts()?;
        println!("The secret contract count: {:?}", contract_count);
        let sc_addresses = self.contract.get_secret_contract_addresses(U256::from(0), contract_count)?;
        println!("The secret contract addresses: {:?}", sc_addresses);
        epoch_marker.confirm(&worker_params, sc_addresses)?;
        Ok(())
    }

    /// Store the epoch marker (first block number of the new epoch) for each
    /// WorkerParametized event emitted by the Enigma contract.
    /// Not in use, this approach has no obvious benefit compared to just waiting for the tx on the main thread.
    /// Consider in context of a possible future optimization
    #[allow(dead_code)]
    pub fn filter_worker_params(&self) {
        let event = WorkersParameterizedEvent::new();
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
                        println!("Got WorkerParameterized log: {:?}", log);
                        let raw_log = RawLog { topics: log.topics, data: log.data.0 };
                        let event = WorkersParameterizedEvent::new();
                        let result = event.0.parse_log(raw_log).unwrap();
                        println!("Parsed the WorkerParameterized event: {:?}", result);
                        // TODO: consider performing a cursory check against EpochSeed
                        Ok(())
                    })
            })
            .map_err(|err| eprintln!("Unable to process WorkersParameterized log: {:?}", err));
        event_future.wait().unwrap();
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use std::env;

    use super::*;

    /// This function is important to enable testing both on the CI server and local.
                                    /// On the CI Side:
                                    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
                                    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
                                    /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:9545")) }
}
