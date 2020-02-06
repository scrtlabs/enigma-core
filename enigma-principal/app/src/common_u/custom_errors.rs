use thiserror::Error;
use failure::Error as GenericErr;
use sgx_types::sgx_status_t;

use enigma_types;
use enigma_tools_u::common_u::errors::Web3Error;

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error(transparent)]
    ConfigError(#[from] ConfigError),
    #[error(transparent)]
    HTTPServerError(#[from] HTTPServerError),
    #[error("Error in Controller: {0}")]
    VerifierError(VerifierError),
    #[error("Error in Controller: {0}")]
    EnclaveError(EnclaveError),
    #[error("Error in Controller: {0}")]
    EpochError(EpochError),
    #[error(transparent)]
    ContractError(#[from] Web3Error),
    #[error("Error while trying to produce quote")]
    QuoteErr,
    #[error("the error received is: {0}")]
    Other(GenericErr)
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Unable to open config file")]
    FileDoesntExist,
    #[error("Unable to convert file content to string")]
    NotAString,
    #[error("Cannot parse data")]
    CouldntParse,
}

#[derive(Error, Debug)]
pub enum HTTPServerError {
    #[error("Input signature got an unexpected size: {0} bytes. Expected 65 bytes.")]
    BadSigLen(usize),
    #[error(transparent)]
    EpochError(#[from] EpochError),
    #[error("an error occurred in the pubkey recovery")]
    KeyRecoveryErr,
    #[error("error while trying to parse the message received")]
    InvalidMessage,
}

#[derive(Error, Debug)]
pub enum EpochError {
    #[error("Epoch has yet to be confirmed")]
    UnconfirmedState,
}

#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("Error inside the enclave: {err:?} with status: {status:?}")]
    Failure {
        err: enigma_types::EnclaveReturn,
        status: sgx_status_t
    },
    #[error("Error returned from inside the enclave")]
    Unspecified,
    #[error(transparent)]
    HTTPServerError(#[from] HTTPServerError),
}

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("Error occurred while trying to create all directories")]
    CreateErr,
    #[error("Error occurred while trying to read the stored SignedEpochs")]
    ReadErr,
    #[error("Error occurred while trying to write to the stored SignedEpochs")]
    WriteErr,
    #[error("Unable to lock the list of epochs")]
    LockErr,
    #[error("An unconfirmed Epoch must be appended only after a confirmed Epoch")]
    UnexpectedUnconfirmedErr,
    #[error("A Confirmed epoch already exists- either the last epoch wasn't stored or confirmation was done")]
    UnexpectedConfirmedErr,
    #[error("Requested epochs don't exist")]
    EpochsDontExistErr,
    #[error(transparent)]
    EpochErr(#[from] EpochError),
    #[error("{0}")]
    Other(String),

}
