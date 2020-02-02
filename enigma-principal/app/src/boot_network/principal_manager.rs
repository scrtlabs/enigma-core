use std::{fs::File, io::prelude::*, str};

use serde_derive::*;
use serde_json;
use sgx_types::sgx_enclave_id_t;
use envy;

use enigma_crypto::EcdsaSign;
use esgx;

use secp256k1::key::SecretKey;
use secp256k1::Message;
use secp256k1::Secp256k1;
use common_u::custom_errors::ConfigError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KMConfig {
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


//
//pub struct ReportManager {
//    pub config: KMConfig,
//    as_service: service::AttestationService,
//    pub eid: sgx_enclave_id_t,
//}

//pub struct PrincipalManager {
//    pub contract: EnigmaContract,
//    report_manager: ReportManager,
//}

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

//impl ReportManager {
//    pub fn new(config: KMConfig, eid: sgx_enclave_id_t) -> Self {
//        let as_service = service::AttestationService::new_with_retries(&config.attestation_service_url, config.attestation_retries);
//        ReportManager { config, as_service, eid }
//    }
//
//    pub fn get_signing_address(&self) -> Result<H160, ReportManagerErr> {
//        esgx::equote::get_register_signing_address(self.eid).or(Err(ReportManagerErr::GetRegisterAddrErr)).into()
//    }
//
//    pub fn get_ethereum_address(&self) -> Result<String, ReportManagerErr> {
//        if self.config.with_private_key {
//            return Ok(self.config.account_address.clone());
//        }
//        let _signing_address = esgx::equote::get_ethereum_address(self.eid).or(Err(ReportManagerErr::GetEtherAddrErr))?;
//        let signing_address = _signing_address.to_vec().to_hex();
//        Ok(signing_address)
//    }
//
//    #[logfn(DEBUG)]
//    pub fn get_registration_params(&self) -> Result<RegistrationParams, ReportManagerErr> {
//        let signing_address = self.get_signing_address()?;
//        let mode = option_env!("SGX_MODE").unwrap_or_default();
//        let enc_quote = retry_quote(self.eid, &self.config.spid, 18).or(Err(ReportManagerErr::QuoteErr))?;
//
//        let report: String;
//        let signature: String;
//        if mode == "SW" {
//            // Software Mode
//            println!("Simulation mode");
//            report = enc_quote;
//            signature = String::new();
//        } else {
//            // Hardware Mode
//            println!("Hardware mode");
//            let response = self.as_service.get_report(enc_quote).or(Err(ReportManagerErr::QuoteErr))?;
//            report = response.result.report_string;
//            signature = response.result.signature;
//        }
//        Ok(RegistrationParams { signing_address, report, signature })
//    }
//}

impl KMConfig {
    // load json config into the struct
    #[logfn(DEBUG)]
    pub fn load_config(config_path: &str) -> Result<KMConfig, ConfigError> {
        info!("loading Principal config");
        // All configurations from env should be with the same names of the
        // PrincipalConfig struct fields in uppercase letters
        match envy::from_env::<KMConfig>() {
            Ok(config) => Ok(config),
            Err(_) => {
                info!("trying to load from path: {:?}", config_path);
                let mut f = File::open(config_path).or(Err(ConfigError::FileDoesntExist))?;

                let mut contents = String::new();
                f.read_to_string(&mut contents).or(Err(ConfigError::NotAString))?;

                serde_json::from_str(&contents).or(Err(ConfigError::Parsing))
            }
        }
    }
}

//// General interface of a Sampler == The entity that manages the principal node logic.
//pub trait Sampler {
//    /// load with config from file
//    fn new(contract: EnigmaContract, report_manager: ReportManager) -> Self;
//
//    fn get_signing_address(&self) -> Result<H160, Error>;
//
//    fn get_contract_address(&self) -> Address;
//
//    fn get_account_address(&self) -> Address;
//
//    fn get_network_url(&self) -> String;
//
//    fn get_block_number(&self) -> Result<U256, Error>;
//
//    fn register<G: Into<U256>>(&self, signing_address: H160, gas_limit: G) -> Result<H256, Error>;
//
//    /// after initiation, this will run the principal node and block.
//    fn run<G: Into<U256>>(&self, path: PathBuf, reset_epoch: bool, gas: G) -> Result<(), Error>;
//}

//impl Sampler for PrincipalManager {
//    fn new(contract: EnigmaContract, report_manager: ReportManager) -> Self {
//        PrincipalManager { contract, report_manager }
//    }
//
//    fn get_signing_address(&self) -> Result<H160, Error> {
//        let sig_addr = self.report_manager.get_signing_address()?;
//        Ok(sig_addr.parse()?)
//    }
//
//
//    fn get_network_url(&self) -> String { self.report_manager.config.url.clone() }
//
////    fn get_block_number(&self) -> Result<U256, Error> {
////        let block_number = self.contract.web3.eth().block_number().wait().
////            map_err(|e| { Web3Error { message: format!("Current block number not available: {:?}", e), }.into()})?
////    }
//
//    /// Warms up the application.
//    /// 1. Register the worker if not already registered
//    /// 2. Create an `EpochProvider` which loads the local `EpochState` if available
//    /// 3. Start the JSON-RPC server
//    /// 4. Watch the blocks for new epochs
//    ///
//    /// # Arguments
//    ///
//    /// * `path` - path to the directory in which we store the epoch state.
//    /// * `reset_epoch` - If true, reset the epoch state
//    /// * `gas_limit` - The gas limit for all Enigma contract transactions
//    #[logfn(INFO)]
//    fn run<G: Into<U256>>(&self, path: PathBuf, reset_epoch: bool, gas_limit: G) -> Result<(), Error> {
//        let gas_limit: U256 = gas_limit.into();
//        self.verify_identity_or_register(gas_limit)?;
//        // get enigma contract
//        // Start the WorkerParameterized Web3 log filter
//        let eid: sgx_enclave_id_t = self.report_manager.eid;
//        let epoch_provider = KMController::new(eid, path, self.contract.clone())?;
//        if reset_epoch {
//            epoch_provider.epoch_state_manager.reset()?;
//        }
//
//        // Start the JSON-RPC Server
//        let port = self.report_manager.config.http_port;
//        let server_ep = &epoch_provider;
//        thread::scope(|s| {
//            s.spawn(|_| {
//                let server = PrincipalHttpServer::new(server_ep, port);
//                server.start();
//            });
//            s.spawn(|_|{
//                // watch blocks
//                let polling_interval = self.report_manager.config.polling_interval;
//                let epoch_size = self.report_manager.config.epoch_size;
//                self.contract.watch_blocks(
//                    epoch_size,
//                    polling_interval,
//                    epoch_provider,
//                    gas_limit,
//                    self.report_manager.config.confirmations as usize,
//                    self.report_manager.config.max_epochs,
//                );
//            });
//        });
//        Ok(())
//    }
//}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    extern crate tempfile;
    use std::{env, path::Path, sync::Arc, time};
    use failure::Error;
    use web3::{futures::{Future, stream::Stream}, types::FilterBuilder, };
    use crossbeam_utils::thread;
    use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
    use controller::epoch_types::{WorkersParameterizedEvent, WORKER_PARAMETERIZED_EVENT};
    use boot_network::deploy_scripts;
    use esgx::general::init_enclave_wrapper;

    use super::*;

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
        let config = KMConfig::load_config("this is not a path").unwrap();
        assert_eq!(config.polling_interval, 1);
        assert_eq!(config.http_port, 3040);
        assert_eq!(config.attestation_retries, 11);
    }
}
