pub mod evm;
pub mod abi;
pub mod error;
pub mod rlp;

use std::vec::Vec;
use enigma_tools_t::common::utils_t::{Sha256, FromHex};
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;

pub enum EvmResult{
    SUCCESS=0,
    FAULT,
}

pub fn get_key() -> Vec<u8> {
    let _my_priv_key = "2987699a6d3a5ebd07f4caf422fad2809dcce942cd9db266ed8e2be02cf95ee9".from_hex().unwrap();
    let mut my_priv_key = [0u8; 32];
    my_priv_key.clone_from_slice(&_my_priv_key);
    let my_keys = KeyPair::from_slice(&my_priv_key).unwrap();
    let _client_pub_key = "5587fbc96b01bfe6482bf9361a08e84810afcc0b1af72a8e4520f98771ea1080681e8a2f9546e5924e18c047fa948591dba098bffaced50f97a41b0050bdab99".from_hex().unwrap();
    let mut client_pub_key = [0u8; 64];
    client_pub_key.clone_from_slice(&_client_pub_key);
    my_keys.get_aes_key(&client_pub_key).unwrap()
}

pub mod preprocessor{
    use std::vec::Vec;
    use sgx_trts::trts::rsgx_read_rand;
    use common::errors_t::EnclaveError;
    use std::string::ToString;
    use common::utils_t::{ToHex, FromHex};


    // TODO: Implement Errors
    pub fn run(pre_sig: &str) -> Result<Vec<u8>, EnclaveError> {
        match pre_sig {
            "rand()" | "rand" => rand(),
            _ => return Err(EnclaveError::PreprocessorError{message: "Unknown preprocessor".to_string()}),
        }
    }
    fn rand() -> Result<Vec<u8>, EnclaveError> {
        let mut r: [u8; 16] = [0; 16];
        match rsgx_read_rand(&mut r) {
            Ok(_) => Ok(r.to_vec()),
            Err(err) => return Err(EnclaveError::PreprocessorError{message: err.to_string()}),
        }
    }

}
