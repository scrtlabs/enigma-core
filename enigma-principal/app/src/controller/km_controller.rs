use std::path::PathBuf;
use std::clone::Clone;

use ethabi::{Log, RawLog};
use sgx_types::sgx_enclave_id_t;
use web3::types::{H256, TransactionReceipt, U256, H160};
use rustc_hex::ToHex;

use enigma_tools_m::keeper_types::InputWorkerParams;
use enigma_tools_u::web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract};
use enigma_tools_u::common_u::errors::Web3Error;
use enigma_tools_u::esgx::equote::retry_quote;
use enigma_tools_u::attestation_service::service::AttestationService;

use controller::km_utils::KMConfig;
use epochs::epoch_keeper_u::set_or_verify_worker_params;
use esgx::equote;
use common_u::custom_errors::{ControllerError, EnclaveError, EpochError};
use epochs::verifier::EpochVerifier;
use epochs::epoch_types::{SignedEpoch, WORKER_PARAMETERIZED_EVENT, WorkersParameterizedEvent};

lazy_static!{ pub static ref GAS_LIMIT: U256 = 5_999_999.into(); }


pub struct KMController {
    pub contract: EnigmaContract,
    pub epoch_verifier: EpochVerifier,
    pub eid: sgx_enclave_id_t,
    pub config: KMConfig,
}

impl KMController {
    pub fn new(eid: sgx_enclave_id_t, dir_path: PathBuf, contract: EnigmaContract, config: KMConfig) -> Result<KMController, ControllerError> {
        let epoch_verifier = EpochVerifier::new(dir_path).map_err(ControllerError::VerifierError)?;
        let controller = Self { contract, epoch_verifier, eid, config };
        controller.verify_worker_params()?;
        Ok(controller)
    }

    /// Find confirmed `EpochState` by block number
    ///
    /// # Arguments
    /// * `block_number` - A block number in the desired epoch
    pub fn find_epoch(&self, block_number: U256) -> Result<SignedEpoch, ControllerError> {
        self.epoch_verifier.get_confirmed_by_block_number(block_number).map_err(ControllerError::VerifierError)
    }

    /// Find the last confirmed `EpochState`
    pub fn find_last_epoch(&self) -> Result<SignedEpoch, ControllerError> {
        if self.epoch_verifier.is_last_unconfirmed().map_err(ControllerError::VerifierError)? {
            return Err(ControllerError::EpochError(EpochError::UnconfirmedState));
        }
        self.epoch_verifier.last(true).map_err(ControllerError::VerifierError)
    }

    #[logfn(DEBUG)]
    fn parse_worker_parameterized(&self, receipt: &TransactionReceipt) -> Result<Log, ControllerError> {
        let log = receipt.logs.get(0).ok_or(Web3Error {
            message: format!("A connection error occurred with the Smart Contract- workerParams did not return a log response" ),
        })?.clone();
        let raw_log = RawLog { topics: log.topics, data: log.data.0 };
        let event = WorkersParameterizedEvent::new();
        let result = event.0.parse_log(raw_log).map_err(|err|
            Web3Error {
                message: format!("Unable to parse {} event: {:?}", WORKER_PARAMETERIZED_EVENT, err),
            })?;
        debug!("Parsed the {} event: {:?}", WORKER_PARAMETERIZED_EVENT, result);
        Ok(result)
    }

    #[logfn(DEBUG)]
    fn verify_worker_params(&self) -> Result<(), ControllerError> {
        for signed_epoch in self.epoch_verifier
            .get_all_confirmed()
            .map_err(ControllerError::VerifierError)?
            .iter()
            {
            // if the epoch is confirmed by the Enigma Contract
            if signed_epoch.confirmed_state.is_some() {
                // Get the km_block_number which indicates where to take the list of active workers from
                let km_block_number = signed_epoch.get_km_block_num();
                let (workers, stakes) = self.contract.get_active_workers(km_block_number).map_err(ControllerError::Other)?;
                let worker_params = InputWorkerParams { km_block_number, workers, stakes };
                set_or_verify_worker_params(self.eid, &worker_params, Some(signed_epoch.clone())).map_err(ControllerError::EnclaveError)?;
            }
        }
        Ok(())
    }

    pub fn get_signing_address(&self) -> Result<H160, ControllerError> {
        Ok(equote::get_register_signing_address(self.eid).
            or( Err(ControllerError::EnclaveError(EnclaveError::Unspecified)))?.into())
    }

//    pub fn get_ethereum_address(&self) -> Result<H160, Error> {
//        if self.config.with_private_key {
//            return Ok(H160::from_slice(&self.config.account_address.clone().from_hex()?));
//        }
//        Ok(equote::get_ethereum_address(self.eid)?.into())
//    }


    #[logfn(DEBUG)]
    fn register(&self) -> Result<H256, ControllerError> {
        let signing_address = self.get_signing_address()?;
        let mode = option_env!("SGX_MODE").unwrap_or_default();
        let mut enc_quote = retry_quote(self.eid, &self.config.spid, 18).or(Err(ControllerError::QuoteErr))?;

        let mut signature = String::new();
        if mode == "HW" {
            // Hardware Mode
            println!("Hardware mode");
            let attestation = AttestationService::new_with_retries(&self.config.attestation_service_url, self.config.attestation_retries);
            let response = attestation.get_report(enc_quote).or(Err(ControllerError::QuoteErr))?;
            enc_quote = response.result.report_string;
            signature = response.result.signature;
        }
        // the register method on the Enigma contract expects a staking address
        // since it's suited for the workers as well.
        // staking is irrelevant for the KM and therefore we are sending an empty address
        let staking_address = H160::zero();
        println!("Registering");
        let receipt = self.contract.register(
            staking_address,
            signing_address,
            enc_quote,
            signature,
            *GAS_LIMIT,
            self.config.confirmations as usize,
        ).map_err(ControllerError::Other)?;
        Ok(receipt.transaction_hash)
    }

    /// Verifies whether the worker is registered in the Enigma contract.
    /// If not, create a `register` transaction.
    #[logfn(DEBUG)]
    pub fn verify_identity_or_register(&self) -> Result<Option<H256>, ControllerError> {
        let signing_address = self.get_signing_address()?;
        let registered_signing_address = self.contract.get_signing_address().map_err(ControllerError::Other)?;
        if signing_address == registered_signing_address {
            debug!("Already registered with enigma signing address {:?}", registered_signing_address);
            Ok(None)
        } else {
            let tx = self.register()?;
            debug!("Registered by transaction {:?}", tx);
            Ok(Some(tx))
        }
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
    /// * `confirmations` - The number of blocks required to confirm the `setWorkersParams` transaction
    pub fn set_worker_params(&self, block_number: U256,  confirmations: usize) -> Result<H256, ControllerError> {
        self.set_worker_params_internal(block_number, confirmations, None)
    }

    #[logfn(DEBUG)]
    fn set_worker_params_internal(&self, km_block_number: U256, confirmations: usize, epoch_state: Option<SignedEpoch>) -> Result<H256, ControllerError> {
        let (workers, stakes) = self.contract.get_active_workers(km_block_number).map_err(ControllerError::Other)?;
        let worker_params = InputWorkerParams { km_block_number, workers, stakes };
        let mut epoch = set_or_verify_worker_params(self.eid, &worker_params, epoch_state).map_err(ControllerError::EnclaveError)?;

        debug!("Storing unconfirmed EpochState: {:?}", epoch);
        self.epoch_verifier.append_unconfirmed(epoch.clone()).map_err(ControllerError::VerifierError)?;

        debug!("Waiting for setWorkerParams({:?}, {:?}, {:?})", km_block_number, epoch.get_seed(), epoch.get_sig());
        let receipt = self.contract
            .set_workers_params(km_block_number, epoch.get_seed(), epoch.get_sig(), *GAS_LIMIT, confirmations)
            .map_err(ControllerError::Other)?;
        debug!("Got the receipt: {:?}", receipt);

        let log = self.parse_worker_parameterized(&receipt)?;
        match log.params.into_iter().find(|x| x.name == "firstBlockNumber") {
            Some(param) => {
                let ether_block_number = param.value.to_uint().unwrap();
                if ether_block_number < km_block_number {
                    Err(Web3Error { message: "The block number given by the Enigma Contract is smaller than the one defined by the KM".to_string() })?;
                }
                self.confirm_epoch(&mut epoch, ether_block_number, worker_params)?;
                debug!("Storing confirmed epoch state: {:?}", epoch);

                self.epoch_verifier.confirm_last(epoch).map_err(ControllerError::VerifierError)?;
                Ok(receipt.transaction_hash)
            }
            None => Err(Web3Error { message: "firstBlockNumber not found in receipt log".to_string() })?,
        }
    }

    /// Build a local mapping of smart contract address => selected worker for the epoch
    ///
    /// # Arguments
    ///
    /// * `epoch_state` - The mutable `EpochState` to be confirmed
    /// * `worker_params` - The `InputWorkerParams` used to run the worker selection algorithm
    #[logfn(DEBUG)]
    pub fn confirm_epoch(&self, epoch_state: &mut SignedEpoch, ether_block_number: U256, worker_params: InputWorkerParams) -> Result<(), ControllerError> {
        let sc_addresses = self.contract.get_all_secret_contract_addresses()
            .map_err(ControllerError::Other)?;

        debug!("The secret contract addresses: {:?}",
               sc_addresses.iter().map(|item| {item.to_hex()}).collect::<Vec<String>>());
        epoch_state.confirm(ether_block_number, &worker_params, sc_addresses);
        Ok(())
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
pub mod test {
    extern crate tempfile;
    use std::collections::HashMap;
    use std::path::Path;
    use self::tempfile::tempdir;
    use web3::futures::Future;
    use web3::types::{Bytes, H160};
    use enigma_types::Hash256;
    use controller::km_utils::{SgxEthereumSigner};
    use enigma_crypto::EcdsaSign;
    use esgx::general::init_enclave_wrapper;
    use epochs::epoch_types::ConfirmedEpochState;
    use super::*;
    use common_u::custom_errors::ConfigError;
    use enigma_tools_u::common_u::errors::Web3Error;

    #[logfn(DEBUG)]
    pub fn get_config() -> Result<KMConfig, ConfigError> {
        let config_path = "../app/tests/principal_node/config/principal_test_config.json";
        let config = KMConfig::load_config(config_path)?;
        Ok(config)
    }

    pub fn init_no_deploy(eid: u64) -> Result<KMController, ControllerError> {
        let config = get_config().map_err(ControllerError::ConfigError)?;
        let ethereum_signer = Box::new(SgxEthereumSigner::new(eid)) as Box<dyn EcdsaSign + Send + Sync>;
        let contract = EnigmaContract::from_deployed(
            &config.enigma_contract_address,
            Path::new(&config.enigma_contract_path),
            Some(&config.account_address),
            config.chain_id,
            &config.url,
            ethereum_signer,
        ).or( Err(ControllerError::ContractError(
            Web3Error{message: String::from("An error occurred while trying to deploy the contract")})))?;
       let path = tempdir().unwrap().into_path();
       KMController::new(eid, path, contract, config)
    }

    #[test]
    #[ignore]
    fn test_set_worker_params() {
        let enclave = init_enclave_wrapper().unwrap();
        let eid = enclave.geteid();
        let controller = init_no_deploy(eid).unwrap();
        controller.verify_identity_or_register().unwrap();

        let block_number = controller.contract.web3.eth().block_number().wait().unwrap();
        controller.epoch_verifier.reset().unwrap();
        controller.set_worker_params(block_number,  0).unwrap();
    }

    pub const WORKER_SIGN_ADDRESS: [u8; 20] =
        [95, 53, 26, 193, 96, 206, 55, 206, 15, 120, 191, 101, 13, 44, 28, 237, 80, 151, 54, 182];

    pub fn setup_epoch_storage_dir() -> PathBuf {
        let tempdir = tempfile::tempdir().unwrap();
        let temp_path = tempdir.into_path();
        println!("path is: {:?}", temp_path);
        temp_path
    }

    // TODO: The two tests below require the Enigma contract to be deployed
    /// Not a standalone unit test, must be coordinated with the Enigma Contract tests
//    #[test]
//    #[ignore]
//    fn test_set_worker_params() {
//        let tempdir = tempfile::tempdir().unwrap();
//        let gas_limit: U256 = 5999999.into();
//        let enclave = init_enclave_wrapper().unwrap();
//        let eid = enclave.geteid();
//        let principal = init_no_deploy(eid).unwrap();
//        principal.verify_identity_or_register(gas_limit).unwrap();
//
//        let block_number = principal.get_block_number().unwrap();
//        let eid_safe = eid;
//        let epoch_provider = KMController::new(eid_safe, tempdir.into_path(), principal.contract.clone()).unwrap();
//        epoch_provider.epoch_state_manager.reset().unwrap();
//        epoch_provider.set_worker_params(block_number, gas_limit, 0).unwrap();
//    }

    /// This test is more like a system-test than a unit-test.
    /// It is only dependent on an ethereum node running under the NODE_URL evn var or the default localhost:8545
    /// First it deploys all the contracts related (EnigmaToken, Enigma) and runs miner to simulate blocks.
    /// Second, it spawns a background thread to poll for events and searchses for the WorkersParameterized event.
    /// Then, the principal register (full process including quote) and then,
    ///  starts watching blocks and emits random with WorkersParameterized event.
    /// The testing is looking for at least 2 emmits of the WorkersParameterized event and compares the event triggerd
    /// If the event name is different or if it takes more than 30 seconds then the test will fail.
//    #[test]
//    #[ignore]
//    fn test_full_principal_logic() {
//        let controller = init_no_deploy(eid).unwrap();
//        let account = controller.get_account_address();
//
//        let contract = &controller.contract;
//        thread::scope(|s| {
//            // run simulated miner
//            s.spawn(|_| {
//                let interval = 1;
//                deploy_scripts::forward_blocks(&controller.contract.web3, interval, account).unwrap();
//            });
//            s.spawn(|_| {
//                let event = WorkersParameterizedEvent::new();
//                let event_sig = event.0.signature();
//                let filter = FilterBuilder::default()
//                    .address(vec![contract.address()])
//                    .topics(Some(vec![event_sig.into()]), None, None, None)
//                    .build();
//
//                let event_future = contract
//                    .web3
//                    .eth_filter()
//                    .create_logs_filter(filter)
//                    .then(|filter| {
//                        filter.unwrap().stream(time::Duration::from_secs(1)).for_each(|log| {
//                            println!("Got {} log: {:?}", WORKER_PARAMETERIZED_EVENT, log);
//                            Ok(())
//                        })
//                    })
//                    .map_err(|err| eprintln!("Unable to process WorkersParameterized log: {:?}", err));
//                event_future.wait().unwrap();
//            });
//            s.spawn(|_| {
//                // run principal
//                controller.run(tempdir.into_path(), true).unwrap();
//            });
//        });
//    }

    #[test]
    fn test_store_epoch_state() {
        let path = setup_epoch_storage_dir();
        let epoch_manager_calculated = EpochVerifier::new(path.clone()).unwrap();

        let mut selected_workers: HashMap<Hash256, H160> = HashMap::new();
        let mock_address = [1u8; 32];
        selected_workers.insert(Hash256::from(mock_address), H160(WORKER_SIGN_ADDRESS));
        let ether_block_number = U256::from(3);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, ether_block_number });

        let seed = U256::from(1);
        let mock_sig = [1u8; 65];
        let sig = Bytes::from(mock_sig.to_vec());
        let nonce = U256::from(0);
        let km_block_number = U256::from(2);

        let mut epoch = SignedEpoch::new(seed, sig, nonce, km_block_number);
        epoch.confirmed_state = confirmed_state;
        epoch_manager_calculated.append_unconfirmed(epoch.clone()).unwrap();

        let epoch_manager_accepted = EpochVerifier::new(path).unwrap();
        assert_eq!(format!("{:?}", epoch_manager_accepted.epoch_list.lock().unwrap().iter().last().unwrap()), format!("{:?}", epoch));
    }

    #[test]
    fn test_store_and_reset_epoch_state() {
        let path = setup_epoch_storage_dir();
        let epoch_manager_calculated = EpochVerifier::new(path.clone()).unwrap();

        let mut selected_workers: HashMap<Hash256, H160> = HashMap::new();
        let mock_address = [1u8; 32];
        selected_workers.insert(Hash256::from(mock_address), H160(WORKER_SIGN_ADDRESS));
        let ether_block_number = U256::from(4);
        let confirmed_state = Some(ConfirmedEpochState { selected_workers, ether_block_number });

        let seed = U256::from(1);
        let mock_sig = [1u8; 65];
        let sig = Bytes::from(mock_sig.to_vec());
        let nonce = U256::from(0);
        let km_block_number = U256::from(4);

        let mut epoch = SignedEpoch::new(seed, sig, nonce, km_block_number);
        epoch.confirmed_state = confirmed_state;
        epoch_manager_calculated.append_unconfirmed(epoch).unwrap();

        epoch_manager_calculated.reset().unwrap();
        let epoch_manager_accepted = EpochVerifier::new(path).unwrap();

        assert!(epoch_manager_accepted.epoch_list.lock().unwrap().is_empty());


    }
}
