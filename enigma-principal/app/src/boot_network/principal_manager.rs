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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KMConfig {
    // Path to IEnigma.Json ** probably a good place to document that IEnigma.Json is used because parsing the entire Enigma.json will fail to due missing types
    pub enigma_contract_path: String,
    // Address of the deployed contract -- expected to be set externally
    pub enigma_contract_address: String,
    // Ethereum address of the *operating address* of the KM
    pub account_address: String,
    // Chain ID of the ethereum node we're working with
    pub chain_id: u64,
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

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    extern crate tempfile;
    use std::env;

    use super::*;

    #[test]
    fn test_load_config_from_env() {
        env::set_var("ENIGMA_CONTRACT_PATH", "../app/tests/principal_node/contracts/IEnigma.json");
        env::set_var("ENIGMA_CONTRACT_ADDRESS", "59d3631c86BbE35EF041872d502F218A39FBa150");
        env::set_var("ACCOUNT_ADDRESS","1df62f291b2e969fb0849d99d9ce41e2f137006e");
        env::set_var("WITH_PRIVATE_KEY", "false");
        env::set_var("PRIVATE_KEY", "");
        env::set_var("URL", "http://172.20.0.2:9545");
        env::set_var("EPOCH_SIZE", "10");
        env::set_var("POLLING_INTERVAL", "1");
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
