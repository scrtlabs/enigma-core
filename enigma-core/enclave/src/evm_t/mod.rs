pub mod abi;
pub mod error;
pub mod evm;

pub enum EvmResult {
    SUCCESS = 0,
    FAULT,
}

pub mod preprocessor {
    use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, FailedTaskError::*, EnclaveSystemError::*};
    use sgx_trts::trts::rsgx_read_rand;
    use std::string::ToString;
    use std::vec::Vec;

    // TODO: Implement Errors
    pub fn run(pre_sig: &str) -> Result<Vec<u8>, EnclaveError> {
        match pre_sig {
            "rand()" | "rand" => rand(),
            _ => Err(FailedTaskError(InputError { message: "Unknown preprocessor".to_string() })),
        }
    }
    fn rand() -> Result<Vec<u8>, EnclaveError> {
        let mut r: [u8; 16] = [0; 16];
        match rsgx_read_rand(&mut r) {
            Ok(_) => Ok(r.to_vec()),
            Err(err) => Err(SystemError(SgxError{ err: format!("{}", err), description: err.__description().to_string() })
            ),
        }
    }

}
