use std::{
    fs::{self, File},
    io::{self, prelude::*},
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use std::clone::Clone;
use std::sync::MutexGuard;

use enigma_tools_m::keeper_types::{InputWorkerParams, EPOCH_CAP};
use ethabi::{Log, RawLog};
use failure::Error;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sgx_types::sgx_enclave_id_t;
use web3::types::{H256, TransactionReceipt, U256};

use common_u::errors::{EpochStateIOErr, EpochStateTransitionErr, EpochStateUndefinedErr};
use enigma_tools_u::{
    esgx::general::storage_dir,
    web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract},
};
use enigma_tools_u::common_u::errors::Web3Error;
use epoch_u::epoch_types::{ConfirmedEpochState, EPOCH_STATE_UNCONFIRMED, EpochState, WORKER_PARAMETERIZED_EVENT, WorkersParameterizedEvent};
use esgx::{epoch_keeper_u::set_or_verify_worker_params, general::ENCLAVE_DIR};
use esgx::general::{EPOCH_DIR, EPOCH_FILE};
use std::mem::replace;

#[derive(Debug)]
pub struct EpochStateManager {
    pub epoch_state_list: Mutex<Vec<EpochState>>,
    pub cap: usize,
    pub state_path: PathBuf,
}

impl EpochStateManager {
    pub fn new(mut state_path: PathBuf, cap: usize) -> Result<Self, Error> {
        state_path.push(EPOCH_DIR);
        if !state_path.exists() {
            fs::create_dir_all(&state_path)?;
        }
        state_path.push(EPOCH_FILE);
        Self::create_from_path(state_path, cap)
    }

    /// create an EpochStateManager object given the path from which we retrieve
    /// the epoch states and the cap amount of epochs to handle backwards.
    fn create_from_path(state_path: PathBuf, cap: usize) -> Result<EpochStateManager, Error> {
        let epoch_states = match File::open(&state_path) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                let mut des = Deserializer::new(&buf[..]);
                let mut data: Vec<EpochState> = Deserialize::deserialize(&mut des).unwrap_or_default();
                println!("Found EpochState list: {:?}", data);
                if cap < data.len() {
                    return Err(EpochStateIOErr { message: format!("The EpochState entries exceed the cap: {}", cap) }.into());
                }
                let mut capped_data = Vec::with_capacity(cap);
                capped_data.append(&mut data);
                capped_data
            }
            Err(_) => {
                println!("No existing epoch state, starting with block 0");
                vec![]
            }
        };
        let epoch_state_list = Mutex::new(epoch_states);
        Ok(EpochStateManager {epoch_state_list, cap, state_path})
    }

    /// Lock the `EpochState` list `Mutex`, or wait and retry
    pub fn lock_guard_or_wait(&self) -> Result<MutexGuard<Vec<EpochState>>, Error> {
        let guard = match self.epoch_state_list.lock() {
            Ok(guard) => guard,
            Err(err) => return Err(EpochStateIOErr {
                message: format!("Cannot lock EpochState: {:?}", err),
            }.into()),
        };
        Ok(guard)
    }

    /// Checks if the latest `EpochState` is unconfirmed
    fn is_last_unconfirmed(&self) -> Result<bool, Error> {
        let guard = self.lock_guard_or_wait()?;
        if guard.is_empty() {
            drop(guard);
            return Ok(false);
        }
        let last = guard.iter().last();
        //TODO: why borrow checker fails here
//        mem::drop(guard);
        let epoch_state = match last {
            Some(epoch_state) => epoch_state,
            None => {
                return Err(EpochStateUndefinedErr {}.into());
            }
        };
        let is_unconfirmed = match &epoch_state.confirmed_state {
            Some(_) => false,
            None => true,
        };
        Ok(is_unconfirmed)
    }

    /// Return a list of all confirmed `EpochState`
    pub fn get_all_confirmed(&self) -> Result<Vec<EpochState>, Error> {
        let guard = self.lock_guard_or_wait()?;
        let mut result: Vec<EpochState> = vec![];
        for epoch_state in guard.iter() {
            if epoch_state.confirmed_state.is_some() {
                result.push(epoch_state.clone());
            }
        }
        Ok(result)
    }

    /// Returns the confirmed `EpochState` for the epoch of the block number
    /// # Arguments
    ///
    /// * `block_number` - A block number in the desired epoch
    pub fn get_confirmed_by_block_number(&self, block_number: U256) -> Result<EpochState, Error> {
        let mut result: Option<&EpochState> = None;
        let epoch_states = self.get_all_confirmed()?;
        for epoch_state in epoch_states.iter() {
            let confirmed: &ConfirmedEpochState = epoch_state.confirmed_state.as_ref().unwrap();
            if confirmed.block_number <= block_number {
                result = Some(epoch_state);
            }
        }
        match result {
            Some(epoch_state) => Ok(epoch_state.clone()),
            None => {
                Err(EpochStateTransitionErr { current_state: EPOCH_STATE_UNCONFIRMED.to_string() }.into())
            }
        }
    }

    /// Returns the most recent `EpochState` stored in memory
    /// # Arguments
    ///
    /// * `exclude_unconfirmed` - Exclude any unconfirmed state
    pub fn last(&self, exclude_unconfirmed: bool) -> Result<EpochState, Error> {
        let guard = self.lock_guard_or_wait()?;
        let mut epoch_state_val: Option<EpochState> = None;
        for epoch_state in guard.iter().rev() {
            if (exclude_unconfirmed && epoch_state.confirmed_state.is_some()) || !exclude_unconfirmed {
                epoch_state_val = Some(epoch_state.clone());
                break;
            }
        }
        drop(guard);
        Ok(epoch_state_val.ok_or(EpochStateUndefinedErr{})?)
    }

    #[logfn(DEBUG)]
    fn store_epoch_state(&self) -> Result<(), Error> {
        let guard = self.lock_guard_or_wait()?;
        let epoch_state_list = guard.deref().clone();
        drop(guard);
        info!("Saving EpochState list to disk: {:?}", epoch_state_list);
        if epoch_state_list.is_empty() {
            return Ok(fs::remove_file(&self.state_path).unwrap_or_else(|_| println!("No epoch state file to remove")));
        }
        let mut file = File::create(&self.state_path).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        let mut buf = Vec::new();
        epoch_state_list.serialize(&mut Serializer::new(&mut buf)).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        file.write_all(&buf).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        info!("Saved EpochState list to: {:?}", &self.state_path);
        Ok(())
    }

    /// Empty the `EpochState` list both in memory and to disk
    pub fn reset(&self) -> Result<(), Error> {
        let mut guard = self.lock_guard_or_wait()?;
        replace(&mut *guard, vec![]);
        drop(guard);
        self.store_epoch_state()
    }

    /// Append a new unconfirmed `EpochState` to the list and persist to disk
    /// # Arguments
    ///
    /// * `epoch_state` - The unconfirmed `EpochState` to append
    pub fn append_unconfirmed(&self, epoch_state: EpochState) -> Result<(), Error> {
        if self.is_last_unconfirmed()? {
            bail!("An unconfirmed EpochState must be appended after a confirmed");
        }
        let mut guard = self.lock_guard_or_wait()?;
        // Remove the first item of the list an shift left if the capacity is reached
        if guard.len() == self.cap {
            let epoch_state = guard.remove(0);
            println!("Removed first EpochState of capped list: {:?}", epoch_state);
        }
        guard.push(epoch_state);
        drop(guard);
        self.store_epoch_state()
    }

    /// Confirm the last unconfirmed `EpochState`
    /// # Arguments
    ///
    /// * `epoch_state` - The confirmed `EpochState`
    pub fn confirm_last(&self, epoch_state: EpochState) -> Result<(), Error> {
        let mut guard = self.lock_guard_or_wait()?;
        if let Some(last) = guard.last_mut() {
            if last.confirmed_state.is_some() {
                bail!("Last EpochState already confirmed: {:?}", last);
            }
            *last = epoch_state;
        } else {
            bail!("Cannot confirm the last EpochState of an empty list");
        }
        drop(guard);
        self.store_epoch_state()
    }
}

pub struct EpochProvider {
    pub contract: Arc<EnigmaContract>,
    pub epoch_state_manager: Arc<EpochStateManager>,
    pub eid: Arc<sgx_enclave_id_t>,
}

impl EpochProvider {
    pub fn new(eid: Arc<sgx_enclave_id_t>, dir_path: PathBuf, contract: Arc<EnigmaContract>) -> Result<EpochProvider, Error> {
        let epoch_state_manager = Arc::new(EpochStateManager::new(dir_path, EPOCH_CAP)?);
        let epoch_provider = Self { contract, epoch_state_manager, eid };
        epoch_provider.verify_worker_params()?;
        Ok(epoch_provider)
    }

    /// Find confirmed `EpochState` by block number
    /// # Arguments
    ///
    /// * `block_number` - A block number in the desired epoch
    pub fn find_epoch(&self, block_number: U256) -> Result<EpochState, Error> {
        self.epoch_state_manager.get_confirmed_by_block_number(block_number)
    }

    /// Find the last confirmed `EpochState`
    pub fn find_last_epoch(&self) -> Result<EpochState, Error> {
        if self.epoch_state_manager.is_last_unconfirmed()? {
            return Err(EpochStateTransitionErr { current_state: format!("{}, waiting for confirmation from Ethereum", EPOCH_STATE_UNCONFIRMED) }.into());
        }
        self.epoch_state_manager.last(true)
    }

    #[logfn(DEBUG)]
    fn parse_worker_parameterized(&self, receipt: &TransactionReceipt) -> Result<Log, Error> {
        let log = receipt.logs[0].clone();
        let raw_log = RawLog { topics: log.topics, data: log.data.0 };
        let event = WorkersParameterizedEvent::new();
        let result = match event.0.parse_log(raw_log) {
            Ok(result) => result,
            Err(err) => return Err(Web3Error {
                message: format!("Unable to parse {} event: {:?}", WORKER_PARAMETERIZED_EVENT, err),
            }.into()),
        };
        info!("Parsed the {} event: {:?}", WORKER_PARAMETERIZED_EVENT, result);
        Ok(result)
    }

    #[logfn(DEBUG)]
    fn verify_worker_params(&self) -> Result<(), Error> {
        for epoch_state in self.epoch_state_manager.get_all_confirmed()?.iter() {
            if let Some(confirmed) = &epoch_state.confirmed_state {
                let block_number = confirmed.block_number;
                let (workers, stakes) = self.contract.get_active_workers(block_number)?;
                let worker_params = InputWorkerParams { block_number, workers, stakes };
                set_or_verify_worker_params(*self.eid, &worker_params, Some(epoch_state.clone()))?;
            }
        }
        Ok(())
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
    pub fn set_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize) -> Result<H256, Error> {
        self.set_worker_params_internal(block_number, gas_limit, confirmations, None)
    }

    /// Similar to `set_worker_params` but using the EpochState in storage
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number marking the active worker list
    /// * `gas_limit` - The gas limit of the `setWorkersParams` transaction
    /// * `confirmations` - The number of blocks required to confirm the `setWorkersParams` transaction
    #[logfn(DEBUG)]
    pub fn confirm_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize) -> Result<H256, Error> {
        if !self.epoch_state_manager.is_last_unconfirmed()? {
            bail!("The last EpochState is already confirmed");
        }
        let epoch_state = self.epoch_state_manager.last(false)?;
        info!("Confirming EpochState by verifying with the enclave and calling setWorkerParams: {:?}", epoch_state);
        self.set_worker_params_internal(block_number, gas_limit, confirmations, Some(epoch_state))
    }

    #[logfn(DEBUG)]
    fn set_worker_params_internal<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize, epoch_state: Option<EpochState>) -> Result<H256, Error> {
        let result = self.contract.get_active_workers(block_number)?;
        let worker_params = InputWorkerParams { block_number, workers: result.0, stakes: result.1 };
        let mut epoch_state = set_or_verify_worker_params(*self.eid, &worker_params, epoch_state)?;
        info!("Storing unconfirmed EpochState: {:?}", epoch_state);
        self.epoch_state_manager.append_unconfirmed(epoch_state.clone())?;
        info!("Waiting for setWorkerParams({:?}, {:?}, {:?})", block_number, epoch_state.seed, epoch_state.sig);
        let receipt = self.contract.set_workers_params(block_number, epoch_state.seed, epoch_state.sig.clone(), gas_limit, confirmations)?;
        info!("Got the receipt: {:?}", receipt);
        let log = self.parse_worker_parameterized(&receipt)?;
        match log.params.into_iter().find(|x| x.name == "firstBlockNumber") {
            Some(param) => {
                let block_number = param.value.to_uint().unwrap();
                self.confirm_epoch(&mut epoch_state, block_number, worker_params)?;
                info!("Storing confirmed EpochState: {:?}", epoch_state);
                self.epoch_state_manager.confirm_last(epoch_state)?;
                Ok(receipt.transaction_hash)
            }
            None => return Err(Web3Error { message: "firstBlockNumber not found in receipt log".to_string() }.into()),
        }
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    ///
    /// # Arguments
    ///
    /// * `epoch_state` - The mutable `EpochState` to be confirmed
    /// * `worker_params` - The `InputWorkerParams` used to run the worker selection algorithm
    #[logfn(DEBUG)]
    pub fn confirm_epoch(&self, epoch_state: &mut EpochState, block_number: U256, worker_params: InputWorkerParams) -> Result<(), Error> {
        let contract_count = self.contract.count_secret_contracts()?;
        info!("The secret contract count: {:?}", contract_count);
        let sc_addresses = self.contract.get_secret_contract_addresses(U256::from(0), contract_count)?;
        info!("The secret contract addresses: {:?}", sc_addresses);
        epoch_state.confirm(block_number, &worker_params, sc_addresses)?;
        Ok(())
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
pub mod test {
    extern crate tempfile;

    use self::tempfile::TempDir;
    use std::collections::HashMap;

    use web3::types::{Bytes, H160};

    use enigma_tools_u::{esgx::general::storage_dir};
    use enigma_types::ContractAddress;

    use super::*;

    pub const WORKER_SIGN_ADDRESS: [u8; 20] =
        [95, 53, 26, 193, 96, 206, 55, 206, 15, 120, 191, 101, 13, 44, 28, 237, 80, 151, 54, 182];

    pub fn setup_epoch_storage_dir() -> PathBuf {
        let tempdir = tempfile::tempdir().unwrap();
        let mut temp_path = tempdir.into_path();
        println!("path is: {:?}", temp_path);
        temp_path
    }

    #[test]
    fn test_store_epoch_state() {
        let path = setup_epoch_storage_dir();
        let cap: usize = 2;
        let epoch_manager_calculated = EpochStateManager::new(path.clone(), cap).unwrap();

        let mut selected_workers: HashMap<ContractAddress, H160> = HashMap::new();
        let mock_address = [1u8; 32];
        selected_workers.insert(ContractAddress::from(mock_address), H160(WORKER_SIGN_ADDRESS));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });

        let seed = U256::from(1);
        let mock_sig = [1u8; 65];
        let sig = Bytes::from(mock_sig.to_vec());
        let nonce = U256::from(0);

        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        epoch_manager_calculated.append_unconfirmed(epoch_state.clone()).unwrap();

        let epoch_manager_accepted = EpochStateManager::new(path, cap).unwrap();
        assert_eq!(format!("{:?}", epoch_manager_accepted.epoch_state_list.lock().unwrap().iter().last().unwrap()), format!("{:?}", epoch_state));
    }

    #[test]
    fn test_store_and_reset_epoch_state() {
        let path = setup_epoch_storage_dir();
        let cap: usize = 2;
        let epoch_manager_calculated = EpochStateManager::new(path.clone(), cap).unwrap();

        let mut selected_workers: HashMap<ContractAddress, H160> = HashMap::new();
        let mock_address = [1u8; 32];
        selected_workers.insert(ContractAddress::from(mock_address), H160(WORKER_SIGN_ADDRESS));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });

        let seed = U256::from(1);
        let mock_sig = [1u8; 65];
        let sig = Bytes::from(mock_sig.to_vec());
        let nonce = U256::from(0);

        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        epoch_manager_calculated.append_unconfirmed(epoch_state.clone()).unwrap();

        epoch_manager_calculated.reset().unwrap();
        let epoch_manager_accepted = EpochStateManager::new(path, cap).unwrap();

        assert!(epoch_manager_accepted.epoch_state_list.lock().unwrap().is_empty());


    }
}
