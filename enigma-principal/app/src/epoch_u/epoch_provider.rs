use std::{
    fs::{self, File},
    io::prelude::*,
    mem,
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use enigma_tools_m::keeper_types::InputWorkerParams;
use ethabi::{Log, RawLog};
use failure::Error;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sgx_types::sgx_enclave_id_t;
use web3::types::{H256, TransactionReceipt, U256};

use enigma_tools_u::{
    esgx::general::storage_dir,
    web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract},
};
use epoch_u::epoch_types::{ConfirmedEpochState, EpochState, WorkersParameterizedEvent};
use esgx::{epoch_keeper_u::set_worker_params, general::ENCLAVE_DIR};

pub struct EpochProvider {
    pub contract: Arc<EnigmaContract>,
    pub epoch_state: Arc<Mutex<Option<EpochState>>>,
    pub eid: Arc<sgx_enclave_id_t>,
}

impl EpochProvider {
    pub fn new(eid: Arc<sgx_enclave_id_t>, contract: Arc<EnigmaContract>) -> Result<EpochProvider, Error> {
        let epoch_state_val = Self::read_epoch_state()?;
        println!("Initializing EpochProvider with EpochState: {:?}", epoch_state_val);
        let epoch_state = Arc::new(Mutex::new(epoch_state_val.clone()));
        let epoch_provider = Self { contract, epoch_state, eid };
        if epoch_state_val.is_some() {
            epoch_provider.verify_worker_params()?;
        }
        Ok(epoch_provider)
    }

    fn get_state_file_path() -> PathBuf {
        let mut path = storage_dir(ENCLAVE_DIR).unwrap();
        path.push("epoch");
        path.push("epoch-state.msgpack");
        path
    }

    #[logfn(DEBUG)]
    pub fn read_epoch_state() -> Result<Option<EpochState>, Error> {
        let epoch_state = match File::open(Self::get_state_file_path()) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                let mut des = Deserializer::new(&buf[..]);
                let epoch_state: Option<EpochState> = match Deserialize::deserialize(&mut des) {
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

    #[logfn(DEBUG)]
    pub fn write_epoch_state(epoch_state: Option<EpochState>) -> Result<(), Error> {
        let path = Self::get_state_file_path();
        match epoch_state {
            Some(epoch_state) => {
                let mut file = File::create(path)?;
                let mut buf = Vec::new();
                epoch_state.serialize(&mut Serializer::new(&mut buf))?;
                file.write_all(&buf)?;
            }
            None => {
                match fs::remove_file(path) {
                    Ok(res) => println!("Epoch state file removed: {:?}", res),
                    Err(_err) => eprintln!("No epoch state file to remove"),
                }
            }
        };
        Ok(())
    }

    #[logfn(DEBUG)]
    fn parse_worker_parameterized(&self, receipt: &TransactionReceipt) -> Result<Log, Error> {
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

    /// Reset the `EpochState` stores in memory
    pub fn reset_epoch_state(&self) -> Result<(), Error> {
        self.set_or_clear_epoch_state(None)
    }

    fn set_epoch_state(&self, epoch_state: EpochState) -> Result<(), Error> {
        self.set_or_clear_epoch_state(Some(epoch_state))
    }

    #[logfn(DEBUG)]
    fn set_or_clear_epoch_state(&self, epoch_state: Option<EpochState>) -> Result<(), Error> {
        println!("Replacing EpochState mutex: {:?}", epoch_state);
        let mut guard = match self.epoch_state.try_lock() {
            Ok(guard) => guard,
            Err(_) => bail!("Unable to lock Epoch Marker Mutex"),
        };
        let prev = mem::replace(&mut *guard, epoch_state.clone());
        println!("Replaced EpochState: {:?} with: {:?}", prev, epoch_state);
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

    #[logfn(DEBUG)]
    fn verify_worker_params(&self) -> Result<(), Error> {
        let epoch_state = self.get_state()?;
        println!("Verifying existing epoch state in the enclave: {:?}", epoch_state);
        match self.get_confirmed() {
            Ok(confirmed) => {
                let block_number = confirmed.block_number;
                let (workers, stakes) = self.contract.get_active_workers(block_number)?;
                let worker_params = InputWorkerParams { block_number, workers, stakes };
                set_worker_params(*self.eid, &worker_params, Some(epoch_state))?;
            },
            Err(_) => {
                println!("Skipping verification of unconfirmed EpochState.");
            }
        };
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
    pub fn confirm_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize) -> Result<H256, Error> {
        let epoch_state = self.get_state()?;
        println!("Confirming EpochState by verifying with the enclave and calling setWorkerParams: {:?}", epoch_state);
        self.set_worker_params_internal(block_number, gas_limit, confirmations, Some(epoch_state))
    }

    fn set_worker_params_internal<G: Into<U256>>(&self, block_number: U256, gas_limit: G, confirmations: usize, epoch_state: Option<EpochState>) -> Result<H256, Error> {
        let result = self.contract.get_active_workers(block_number)?;
        let worker_params = InputWorkerParams { block_number, workers: result.0, stakes: result.1 };
        let mut epoch_state = set_worker_params(*self.eid, &worker_params, epoch_state)?;
        println!("Storing unconfirmed EpochState: {:?}", epoch_state);
        self.set_epoch_state(epoch_state.clone())?;
        println!("Waiting for setWorkerParams({:?}, {:?}, {:?})", block_number, epoch_state.seed, epoch_state.sig);
        let receipt = self.contract.set_workers_params(block_number, epoch_state.seed, epoch_state.sig.clone(), gas_limit, confirmations)?;
        println!("Got the receipt: {:?}", receipt);
        let log = self.parse_worker_parameterized(&receipt)?;
        match log.params.into_iter().find(|x| x.name == "firstBlockNumber") {
            Some(param) => {
                let block_number = param.value.to_uint().unwrap();
                self.confirm_epoch(&mut epoch_state, block_number, worker_params)?;
                println!("Storing confirmed EpochState: {:?}", epoch_state);
                self.set_epoch_state(epoch_state)?;
                Ok(receipt.transaction_hash)
            }
            None => bail!("firstBlockNumber not found in receipt log"),
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
        println!("The secret contract count: {:?}", contract_count);
        let sc_addresses = self.contract.get_secret_contract_addresses(U256::from(0), contract_count)?;
        println!("The secret contract addresses: {:?}", sc_addresses);
        epoch_state.confirm(block_number, &worker_params, sc_addresses)?;
        Ok(())
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
pub mod test {
    use web3::types::{Bytes, H160};

    use enigma_crypto::KeyPair;
    use enigma_tools_u::{esgx::general::storage_dir};
    use enigma_types::ContractAddress;
    use esgx::general::EPOCH_DIR;

    use super::*;

    pub const WORKER_SIGN_ADDRESS: [u8; 20] =
        [95, 53, 26, 193, 96, 206, 55, 206, 15, 120, 191, 101, 13, 44, 28, 237, 80, 151, 54, 182];

    pub fn setup_epoch_storage() {
        let mut storage_path = storage_dir(ENCLAVE_DIR).unwrap();
        storage_path.push(EPOCH_DIR);
        // Cleaning-up the epoch data if it exists to start with new state
        if storage_path.is_dir() {
            println!("Deleting epoch directory: {:?}", storage_path);
            fs::remove_dir_all(storage_path.clone()).unwrap_or_else(|_| println!("Epoch dir already removed"));
        }
        fs::create_dir_all(storage_path).unwrap();
    }

    #[test]
    fn test_write_epoch_state() {
        setup_epoch_storage();
        let mut selected_workers: HashMap<ContractAddress, H160> = HashMap::new();
        let mock_address: [u8; 32] = [1; 32];
        selected_workers.insert(ContractAddress::from(mock_address), H160(WORKER_SIGN_ADDRESS));
        let block_number = U256::from(1);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, block_number });
        let seed = U256::from(1);
        let mock_sig: [u8; 65] = [1; 65];
        let sig = Bytes::from(mock_sig.to_vec());
        let nonce = U256::from(0);
        let epoch_state = EpochState { seed, sig, nonce, confirmed_state };
        EpochProvider::write_epoch_state(Some(epoch_state.clone())).unwrap();

        let saved_epoch_state = EpochProvider::read_epoch_state().unwrap();
        assert_eq!(format!("{:?}", saved_epoch_state.unwrap()), format!("{:?}", epoch_state));
    }
}
