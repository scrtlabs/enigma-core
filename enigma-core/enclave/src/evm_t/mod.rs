pub mod evm;
pub mod abi;
pub mod error;
pub mod rlp;

use std::vec::Vec;
use enigma_tools_t::common::utils_t::{Sha256};

pub enum EvmResult{
    SUCCESS=0,
    FAULT,
}

pub fn get_key() -> Vec<u8> {
    b"EnigmaMPC".sha256().to_vec()
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
