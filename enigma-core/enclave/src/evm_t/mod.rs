pub mod evm;
pub mod abi;
pub mod error;

pub enum EvmResult{
    SUCCESS=0,
    FAULT,
}

pub mod preprocessor{
    use std::vec::Vec;
    use sgx_trts::trts::rsgx_read_rand;
    use common::errors_t::EnclaveError;
    use std::string::ToString;


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
