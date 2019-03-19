use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::mem;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time;

use ethabi::{Log, RawLog};
use failure::Error;
use serde_json;
// general
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::{FilterBuilder, H256, TransactionReceipt, U256};

use enigma_tools_u::web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract};
use epoch_u::epoch_types::{ConfirmedEpochState, EpochState, WorkersParameterizedEvent};
use esgx::epoch_keeper_u::set_worker_params;
use esgx::general::{ENCLAVE_DIR, storage_dir};
use keys_u::keeper_types_u::InputWorkerParams;
use sgx_types::sgx_enclave_id_t;

pub struct EpochProvider {
    pub contract: Arc<EnigmaContract>,
    pub epoch_state: Arc<Mutex<Option<EpochState>>>,
    pub eid: Arc<sgx_enclave_id_t>,
}

impl EpochProvider {
    pub fn new(eid: Arc<sgx_enclave_id_t>, contract: Arc<EnigmaContract>) -> Result<EpochProvider, Error> {
        let epoch_state_val = Self::read_epoch_state()?;
        // TODO: If the state is not empty, get the active workers and prove them to the enclave
        println!("Initializing EpochProvider with EpochState: {:?}", epoch_state_val);
        let epoch_state = Arc::new(Mutex::new(epoch_state_val));
        Ok(Self { contract, epoch_state, eid })
    }

    fn get_state_file_path() -> PathBuf {
        let mut path = storage_dir();
        path.join(ENCLAVE_DIR);
        path.push("epoch-state.json");
        path
    }

    /// Reset the `EpochState` stores in memory
    pub fn reset_epoch_state(&self) -> Result<(), Error> {
        self.set_epoch_state(None)?;
        Ok(())
    }

    #[logfn(DEBUG)]
    fn read_epoch_state() -> Result<Option<EpochState>, Error> {
        let epoch_state = match File::open(Self::get_state_file_path()) {
            Ok(mut f) => {
                let mut data = String::new();
                f.read_to_string(&mut data)?;
                let epoch_state: Option<EpochState> = match serde_json::from_str(&data) {
                    Ok(value) => Some(value),
                    Err(err) => {
                        eprintln!("Unable to read block state file: {:?}", err);
                        None
                    }
                };
                epoch_state
            }
            Err(_) => {
                println!("No existing epoch state, starting with block 0");
                None
            }
        };
        Ok(epoch_state)
    }

    fn write_epoch_state(epoch_state: Option<EpochState>) -> Result<(), Error> {
        let path = Self::get_state_file_path();
        if epoch_state.is_some() {
            let mut file = File::create(path)?;
            let contents = serde_json::to_string(&epoch_state.unwrap())?;
            file.write_all(contents.as_bytes())?;
        } else {
            match fs::remove_file(path) {
                Ok(res) => println!("Epoch state file removed: {:?}", res),
                Err(err) => println!("No epoch state file to remove"),
            }
        }
        Ok(())
    }

    #[logfn(DEBUG)]
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

    /// Returns the `EpochState` stored in memory
    pub fn get_state(&self) -> Result<EpochState, Error> {
        let guard = match self.epoch_state.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex."),
        };
        let epoch_state = match guard.deref() {
            Some(epoch_state) => epoch_state.clone(),
            None => bail!("EpochState not set."),
        };
        mem::drop(guard);
        Ok(epoch_state)
    }

    #[logfn(DEBUG)]
    fn set_epoch_state(&self, epoch_state: Option<EpochState>) -> Result<(), Error> {
        println!("Replacing EpochMaker mutex: {:?}", epoch_state);
        let mut guard = match self.epoch_state.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex"),
        };
        let prev = mem::replace(&mut *guard, epoch_state.clone());
        println!("Replaced EpochMaker: {:?} with: {:?}", prev, epoch_state);
        mem::drop(guard);
        match Self::write_epoch_state(epoch_state) {
            Ok(_) => println!("Stored the Epoch Marker to disk"),
            Err(err) => bail!(err),
        };
        Ok(())
    }

    /// Get the confirmed state if available. Bail if not.
    /// The confirmed state contains the selected worker cache.
    pub fn get_confirmed(&self) -> Result<ConfirmedEpochState, Error> {
        let guard = match self.epoch_state.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex."),
        };
        let confirmed_state = match guard.deref() {
            Some(epoch_state) => match &epoch_state.confirmed_state {
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
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number marking the active worker list
    /// * `gas_limit` - The gas limit of the `setWorkersParams` transaction
    /// * `confirmations` - The number of blocks required to confirm the `setWorkersParams` transaction
    ///
    pub fn set_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize) -> Result<(H256), Error> {
        let result = self.contract.get_active_workers(block_number)?;
        let worker_params: InputWorkerParams = InputWorkerParams {
            block_number,
            workers: result.0,
            stakes: result.1,
        };
        println!("The active workers: {:?}", worker_params);
        let epoch_state = &mut set_worker_params(*self.eid, worker_params.clone())?;
        println!("Waiting for setWorkerParams({:?}, {:?}, {:?})", block_number, epoch_state.seed, epoch_state.sig);
        // TODO: Consider a retry mechanism, either store the EpochSeed or add a getter ecall
        let receipt = self.contract.set_workers_params(block_number, epoch_state.seed, epoch_state.sig.clone(), gas_limit, confirmations)?;
        println!("Got the receipt: {:?}", receipt);
        let log = self.parse_worker_parameterized(&receipt)?;
        match log.params.iter().find(|&x| x.name == "firstBlockNumber") {
            Some(param) => {
                println!("Caching selected workers");
                let token = param.value.clone();
                let block_number = token.to_uint().unwrap();
                self.confirm_epoch(epoch_state, block_number, worker_params)?;
                self.set_epoch_state(Some(epoch_state.clone()))?;
                Ok(receipt.transaction_hash)
            }
            None => bail!("firstBlockNumber not found in receipt log")
        }
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    ///
    /// # Arguments
    ///
    /// * `epoch_state` - The mutable `EpochState` to be confirmed
    /// * `worker_params` - The `InputWorkerParams` used to run the worker selection algorithm
    ///
    #[logfn(DEBUG)]
    pub fn confirm_epoch(&self, epoch_state: &mut EpochState, block_number: U256, worker_params: InputWorkerParams) -> Result<(), Error> {
        let contract_count = self.contract.count_secret_contracts()?;
        println!("The secret contract count: {:?}", contract_count);
        let sc_addresses = self.contract.get_secret_contract_addresses(U256::from(0), contract_count)?;
        println!("The secret contract addresses: {:?}", sc_addresses);
        epoch_state.confirm(block_number, &worker_params, sc_addresses)?;
        Ok(())
    }

    /// Store the epoch state (first block number of the new epoch) for each
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
