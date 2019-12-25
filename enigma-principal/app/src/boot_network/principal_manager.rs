use std::{fs::File, io::prelude::*, str, sync::Arc, thread};

use failure::Error;
use rustc_hex::ToHex;
use serde_derive::*;
use serde_json;
use sgx_types::sgx_enclave_id_t;
use web3::{
    futures::Future,
    transports::Http,
    types::{Address, H160, H256, U256},
    Web3,
};
use envy;

use enigma_crypto::EcdsaSign;
use boot_network::{deploy_scripts, keys_provider_http::PrincipalHttpServer, principal_utils::Principal};
use enigma_tools_u::{
    attestation_service::service,
    esgx::equote::retry_quote,
    web3_utils::enigma_contract::{ContractFuncs, ContractQueries, EnigmaContract},
};
use epoch_u::epoch_provider::EpochProvider;
use esgx;
use enigma_tools_u::common_u::errors::Web3Error;
use std::path::PathBuf;

use secp256k1::key::SecretKey;
use secp256k1::Message;
use secp256k1::Secp256k1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalConfig {
    // Path to IEnigma.Json ** probably a good place to document that IEnigma.Json is used because parsing the entire Enigma.json will fail to due missing types
    pub enigma_contract_path: String,
    // Not 100% sure on this one. Path to where we download the enigma.json ABI from? Either way, probably unused
    pub enigma_contract_remote_path: String,
    // Address of the deployed contract -- expected to be set externally
    pub enigma_contract_address: String,
    // Ethereum address of the *operating address* of the KM
    pub account_address: String,
    // Chain ID of the ethereum node we're working with
    pub chain_id: u64,
    // TODO: Not sure what this does
    pub test_net: bool,
    // Flag whether we're using a predefined private key (true) or self-generated keys in SGX (false)
    pub with_private_key: bool,
    // Private key, as hex string (without "0x"). Only used if with_private_key is set to true
    pub private_key: String,
    // Uh
    pub url: String,
    // Length of epoch in blocks
    pub epoch_size: usize,
    // TODO: this
    pub polling_interval: u64,
    // TODO: this
    pub max_epochs: Option<usize>,
    // TODO: this
    pub spid: String,
    // Address of SGX attestation proxy (enigma attestation service)
    pub attestation_service_url: String,
    // Number of retires before we give up on connection to attestation service?
    pub attestation_retries: u32,
    // JSON-RPC port. Usually 3040
    pub http_port: u16,
    // Number of confirmations on-chain before accepting a transaction as complete
    pub confirmations: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrationParams {
    pub signing_address: String,
    pub report: String,
    pub signature: String,
}

pub struct ReportManager {
    pub config: PrincipalConfig,
    as_service: service::AttestationService,
    pub eid: sgx_enclave_id_t,
}

pub struct PrincipalManager {
    pub config: PrincipalConfig,
    pub contract: Arc<EnigmaContract>,
    pub report_manager: ReportManager,
    pub eid: sgx_enclave_id_t,
}

pub struct SgxEthereumSigner {
    eid: sgx_enclave_id_t,
}

impl SgxEthereumSigner {
    pub fn new(eid: sgx_enclave_id_t) -> SgxEthereumSigner {
        SgxEthereumSigner{ eid }
    }
}

impl EcdsaSign for SgxEthereumSigner {
    fn sign_hashed(&self, to_sign: &[u8; 32]) -> [u8; 65] {
        match esgx::equote::sign_ethereum(self.eid, to_sign) {
            Ok(sig) => sig,
            Err(err) => {
                panic!("Error signing data: {:?}", err);
            }
            // println!("Signed data: {:?}", sig.to_vec().to_hex());
        }
    }
}

pub struct PrivateKeyEthereumSigner {
    private_key: [u8; 32]
}

impl PrivateKeyEthereumSigner {
    pub fn new(private_key: [u8; 32]) -> PrivateKeyEthereumSigner {
        PrivateKeyEthereumSigner{ private_key }
    }
}

impl EcdsaSign for PrivateKeyEthereumSigner {
    fn sign_hashed(&self, to_sign: &[u8; 32]) -> [u8; 65] {
        let s = Secp256k1::signing_only();
        let msg = Message::from_slice(to_sign).unwrap();
        let key = SecretKey::from_slice(&self.private_key).unwrap();
        let (v, sig_bytes) = s.sign_recoverable(&msg, &key).serialize_compact();

        let mut sig_recoverable: [u8; 65] = [0u8; 65];
        sig_recoverable[0..64].copy_from_slice(&sig_bytes);
        sig_recoverable[64] = (v.to_i32() + 27) as u8;
        sig_recoverable
    }
}

impl ReportManager {
    pub fn new(config: PrincipalConfig, eid: sgx_enclave_id_t) -> Result<Self, Error> {
        let as_service = service::AttestationService::new_with_retries(&config.attestation_service_url, config.attestation_retries);
        Ok(ReportManager { config, as_service, eid })
    }

    pub fn get_signing_address(&self) -> Result<String, Error> {
        let _signing_address = esgx::equote::get_register_signing_address(self.eid)?;
        let signing_address = _signing_address.to_vec().to_hex();
        Ok(signing_address)
    }

    pub fn get_ethereum_address(&self) -> Result<String, Error> {
        if self.config.with_private_key {
            return Ok(self.config.account_address.clone());
        }
        let _signing_address = esgx::equote::get_ethereum_address(self.eid)?;
        let signing_address = _signing_address.to_vec().to_hex();
        Ok(signing_address)
    }

    #[logfn(DEBUG)]
    pub fn get_registration_params(&self) -> Result<RegistrationParams, Error> {
        let signing_address = self.get_signing_address()?;
        let mode = option_env!("SGX_MODE").unwrap_or_default();
        let enc_quote = retry_quote(self.eid, &self.config.spid, 18)?;

        let report: String;
        let signature: String;
        if mode == "SW" {
            // Software Mode
            println!("Simulation mode");
            report = enc_quote;
            signature = String::new();
        } else {
            // Hardware Mode
            println!("Hardware mode");
            let response = self.as_service.get_report(enc_quote)?;
            report = response.result.report_string;
            signature = response.result.signature;
        }
        Ok(RegistrationParams { signing_address, report, signature })
    }
}

impl PrincipalConfig {
    // load json config into the struct
    #[logfn(DEBUG)]
    pub fn load_config(config_path: &str) -> Result<PrincipalConfig, Error> {
        info!("loading Principal config");
        // All configurations from env should be with the same names of the
        // PrincipalConfig struct fields in uppercase letters
        match envy::from_env::<PrincipalConfig>() {
            Ok(config) => Ok(config),
            Err(_) => {
                info!("trying to load from path: {:?}", config_path);
                let mut f = File::open(config_path)?;

                let mut contents = String::new();
                f.read_to_string(&mut contents)?;

                Ok(serde_json::from_str(&contents)?)
            }
        }
    }
}
impl PrincipalManager {
    pub fn get_web3(&self) -> Arc<Web3<Http>> { Arc::clone(&self.contract.web3) }
}

// General interface of a Sampler == The entity that manages the principal node logic.
pub trait Sampler {
    /// load with config from file
    fn new(config: PrincipalConfig, contract: Arc<EnigmaContract>, report_manager: ReportManager) -> Result<Self, Error>
        where Self: Sized;

    fn get_signing_address(&self) -> Result<H160, Error>;

    fn get_contract_address(&self) -> Address;

    fn get_account_address(&self) -> Address;

    fn get_network_url(&self) -> String;

    fn get_block_number(&self) -> Result<U256, Error>;

    fn register<G: Into<U256>>(&self, signing_address: H160, gas_limit: G) -> Result<H256, Error>;

    fn verify_identity_or_register<G: Into<U256>>(&self, gas_limit: G) -> Result<Option<H256>, Error>;

    /// after initiation, this will run the principal node and block.
    fn run<G: Into<U256>>(&self, path: PathBuf, reset_epoch: bool, gas: G) -> Result<(), Error>;
}

impl Sampler for PrincipalManager {
    fn new(config: PrincipalConfig, contract: Arc<EnigmaContract>, report_manager: ReportManager) -> Result<Self, Error> {
        let eid = report_manager.eid;
        //        let registration_params = report_manager.get_registration_params()?;
        Ok(PrincipalManager { config, contract, report_manager, eid })
    }

    fn get_signing_address(&self) -> Result<H160, Error> {
        let sig_addr = self.report_manager.get_signing_address()?;
        Ok(sig_addr.parse()?)
    }

    fn get_contract_address(&self) -> Address { self.contract.address() }

    // noinspection RsBorrowChecker
    fn get_account_address(&self) -> Address { self.contract.account }

    fn get_network_url(&self) -> String { self.config.url.clone() }

    fn get_block_number(&self) -> Result<U256, Error> {
        let block_number = match self.get_web3().eth().block_number().wait() {
            Ok(block_number) => block_number,
            Err(err) => return Err(Web3Error {
                message: format!("Current block number not available: {:?}", err),
            }.into()),
        };
        Ok(block_number)
    }

    #[logfn(DEBUG)]
    fn register<G: Into<U256>>(&self, signing_address: H160, gas_limit: G) -> Result<H256, Error> {
        let registration_params = self.report_manager.get_registration_params()?;
        // the register method on the Enigma contract expects a staking address
        // since it's suited for the workers as well.
        // staking is irrelevant for the KM and therefore we are sending an empty address
        let staking_address = H160::zero();
        println!("Registering");
        let receipt = self.contract.register(
            staking_address,
            signing_address,
            registration_params.report,
            registration_params.signature,
            gas_limit,
            self.config.confirmations as usize,
        )?;
        Ok(receipt.transaction_hash)
    }

    /// Verifies whether the worker is registered in the Enigma contract.
    /// If not, create a `register` transaction.
    ///
    /// # Arguments
    ///
    /// * `gas_limit` - The gas limit of the `register` transaction
    #[logfn(DEBUG)]
    fn verify_identity_or_register<G: Into<U256>>(&self, gas_limit: G) -> Result<Option<H256>, Error> {
        let signing_address = self.get_signing_address()?;
        let registered_signing_address = self.contract.get_signing_address()?;
        if signing_address == registered_signing_address {
            debug!("Already registered with enigma signing address {:?}", registered_signing_address);
            Ok(None)
        } else {
            let tx = self.register(signing_address, gas_limit)?;
            debug!("Registered by transaction {:?}", tx);
            Ok(Some(tx))
        }
    }

    /// Warms up the application.
    /// 1. Register the worker if not already registered
    /// 2. Create an `EpochProvider` which loads the local `EpochState` if available
    /// 3. Start the JSON-RPC server
    /// 4. Watch the blocks for new epochs
    ///
    /// # Arguments
    ///
    /// * `path` - path to the directory in which we store the epoch state.
    /// * `reset_epoch` - If true, reset the epoch state
    /// * `gas_limit` - The gas limit for all Enigma contract transactions
    #[logfn(INFO)]
    fn run<G: Into<U256>>(&self, path: PathBuf, reset_epoch: bool, gas_limit: G) -> Result<(), Error> {
        let gas_limit: U256 = gas_limit.into();
        self.verify_identity_or_register(gas_limit)?;
        // get enigma contract
        // Start the WorkerParameterized Web3 log filter
        let eid: Arc<sgx_enclave_id_t> = Arc::new(self.eid);
        let epoch_provider = Arc::new(EpochProvider::new(eid, path, self.contract.clone())?);
        if reset_epoch {
            epoch_provider.epoch_state_manager.reset()?;
        }

        // Start the JSON-RPC Server
        let port = self.config.http_port;
        let server_ep = Arc::clone(&epoch_provider);
        thread::spawn(move || {
            let server = PrincipalHttpServer::new(server_ep, port);
            server.start();
        });

        // watch blocks
        let polling_interval = self.config.polling_interval;
        let epoch_size = self.config.epoch_size;
        self.contract.watch_blocks(
            epoch_size,
            polling_interval,
            epoch_provider,
            gas_limit,
            self.config.confirmations as usize,
            self.config.max_epochs,
        );
        Ok(())
    }
}

/// Helper method to start 'miner' that simulates blocks.
pub fn run_miner(account: Address, w3: Arc<Web3<Http>>, interval: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        deploy_scripts::forward_blocks(&Arc::clone(&w3), interval, account).unwrap();
    })
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    extern crate tempfile;
    use std::{env, path::Path, sync::Arc, sync::Mutex, thread, time};
    use self::tempfile::TempDir;

    use web3::{
        futures::{Future, stream::Stream},
        transports::Http,
        types::{FilterBuilder, Log},
        Web3,
    };

    use enigma_tools_u::web3_utils::{enigma_contract::EnigmaContract, w3utils};
    use epoch_u::epoch_types::{WorkersParameterizedEvent, WORKER_PARAMETERIZED_EVENT};
    use esgx::general::init_enclave_wrapper;

    use super::*;

    const GAS_LIMIT: usize = 5999999;
    /// This function is important to enable testing both on the CI server and local.
        /// On the CI Side:
        /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
        /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
        /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:8545")) }

    /// helps in assertion to check if a random event was indeed broadcast.
    pub fn filter_random(w3: &Arc<Web3<Http>>, contract_addr: Option<&str>, event_name: &str) -> Result<Vec<Log>, Error> {
        let logs = w3utils::filter_blocks(w3, contract_addr, event_name)?;
        Ok(logs)
    }

    #[logfn(DEBUG)]
    pub fn get_config() -> Result<PrincipalConfig, Error> {
        let config_path = "../app/tests/principal_node/config/principal_test_config.json";
        let config = PrincipalConfig::load_config(config_path)?;
        Ok(config)
    }

    pub fn init_no_deploy(eid: u64) -> Result<PrincipalManager, Error> {
        let mut config = get_config()?;
        let enclave_manager = ReportManager::new(config.clone(), eid)?;
        let ethereum_signer = Box::new(SgxEthereumSigner{eid}) as Box<dyn EcdsaSign + Send + Sync>;
        let contract = Arc::new(EnigmaContract::from_deployed(
            &config.enigma_contract_address,
            Path::new(&config.enigma_contract_path),
            Some(&config.account_address),
            config.chain_id,
            &config.url,
            ethereum_signer,
        )?);
        let _gas_limit = 5_999_999;
        config.max_epochs = None;
        let principal: PrincipalManager = PrincipalManager::new(config.clone(), contract, enclave_manager).unwrap();
        Ok(principal)
    }

    // TODO: The two tests below require the Enigma contract to be deployed
    /// Not a standalone unit test, must be coordinated with the Enigma Contract tests
    #[test]
    #[ignore]
    fn test_set_worker_params() {
        let tempdir = tempfile::tempdir().unwrap();
        let gas_limit: U256 = 5999999.into();
        let enclave = init_enclave_wrapper().unwrap();
        let eid = enclave.geteid();
        let principal = init_no_deploy(eid).unwrap();
        principal.verify_identity_or_register(gas_limit).unwrap();

        let block_number = principal.get_block_number().unwrap();
        let eid_safe = Arc::new(eid);
        let epoch_provider = EpochProvider::new(eid_safe, tempdir.into_path(), principal.contract.clone()).unwrap();
        epoch_provider.epoch_state_manager.reset().unwrap();
        epoch_provider.set_worker_params(block_number, gas_limit, 0).unwrap();
    }

    /// This test is more like a system-test than a unit-test.
    /// It is only dependent on an ethereum node running under the NODE_URL evn var or the default localhost:8545
    /// First it deploys all the contracts related (EnigmaToken, Enigma) and runs miner to simulate blocks.
    /// Second, it spawns a background thread to poll for events and searchses for the WorkersParameterized event.
    /// Then, the principal register (full process including quote) and then,
    ///  starts watching blocks and emits random with WorkersParameterized event.
    /// The testing is looking for atleast 2 emmits of the WorkersParameterized event and compares the event triggerd
    /// If the event name is different or if it takes more than 30 seconds then the test will fail.
    #[test]
    #[ignore]
    fn test_full_principal_logic() {
        let tempdir = tempfile::tempdir().unwrap();
        let _gas_limit: U256 = 5999999.into();
        let enclave = init_enclave_wrapper().unwrap();
        let eid = enclave.geteid();
        let principal = init_no_deploy(eid).unwrap();
        let account = principal.get_account_address();

        // run simulated miner
        run_miner(account, Arc::clone(&principal.contract.web3), 1);

        let contract = Arc::clone(&principal.contract);
        let child = thread::spawn(move || {
            let event = WorkersParameterizedEvent::new();
            let event_sig = event.0.signature();
            let filter = FilterBuilder::default()
                .address(vec![contract.address()])
                .topics(Some(vec![event_sig.into()]), None, None, None)
                .build();

            let event_future = contract
                .web3
                .eth_filter()
                .create_logs_filter(filter)
                .then(|filter| {
                    filter.unwrap().stream(time::Duration::from_secs(1)).for_each(|log| {
                        println!("Got {} log: {:?}", WORKER_PARAMETERIZED_EVENT, log);
                        Ok(())
                    })
                })
                .map_err(|err| eprintln!("Unable to process WorkersParameterized log: {:?}", err));
            event_future.wait().unwrap();
        });

        // run principal
        principal.run(tempdir.into_path(), true, GAS_LIMIT).unwrap();
        child.join().unwrap();
    }

    #[test]
    fn test_load_config_from_env() {
        env::set_var("ENIGMA_CONTRACT_PATH", "../app/tests/principal_node/contracts/IEnigma.json");
        env::set_var("ENIGMA_CONTRACT_REMOTE_PATH","");
        env::set_var("ENIGMA_CONTRACT_ADDRESS", "59d3631c86BbE35EF041872d502F218A39FBa150");
        env::set_var("ACCOUNT_ADDRESS","1df62f291b2e969fb0849d99d9ce41e2f137006e");
        env::set_var("TEST_NET","true");
        env::set_var("WITH_PRIVATE_KEY", "false");
        env::set_var("PRIVATE_KEY", "");
        env::set_var("URL", "http://172.20.0.2:9545");
        env::set_var("EPOCH_SIZE", "10");
        env::set_var("POLLING_INTERVAL", "1");
        env::set_var("MAX_EPOCHS","10");
        env::set_var("SPID", "B0335FD3BC1CCA8F804EB98A6420592D");
        env::set_var("ATTESTATION_SERVICE_URL", "https://sgx.enigma.co/api");
        env::set_var("ATTESTATION_RETRIES", "11");
        env::set_var("HTTP_PORT","3040");
        env::set_var("CONFIRMATIONS","0");
        env::set_var("CHAIN_ID", "13");
        let config = PrincipalConfig::load_config("this is not a path").unwrap();
        assert_eq!(config.polling_interval, 1);
        assert_eq!(config.http_port, 3040);
        assert_eq!(config.attestation_retries, 11);
    }
}
