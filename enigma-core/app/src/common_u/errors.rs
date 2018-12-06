#![allow(dead_code,unused_assignments,unused_variables)]
use failure::Error;
use sgx_types::*;
use std::fmt;

// error while requesting to produce a quote (registration)
#[derive(Fail, Debug)]
#[fail(display = "Error while producing a quote sgx_status = {}. info = ({})", status, message)]
pub struct ProduceQuoteErr {
    pub status: sgx_status_t,
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while decoding the quote = ({})", message)]
pub struct QuoteErr {
    pub message: String,
}

// error while requesting the public signing key (the registration key)
#[derive(Fail, Debug)]
#[fail(display = "Error while retrieving the registration signing public key sgx_status = {}. info = ({})", status, message)]
pub struct GetRegisterKeyErr {
    pub status: sgx_status_t,
    pub message: String,
}

// error while requesting execevm computation
#[derive(Fail, Debug)]
#[fail(display = "Error doing execevm command sgx_status = {}. info = ({})", status, message)]
pub struct ExecEvmErr {
    pub status: sgx_status_t,
    pub message: String,
}

// error while request attestation service
#[derive(Fail, Debug)]
#[fail(display = "Error while using the attestation service info = ({})", message)]
pub struct AttestationServiceErr {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while trying to {}, Because: {}", command, kind)]
pub struct DBErr {
    pub command: String,
    pub kind: DBErrKind,
    #[fail(cause)]
    pub previous: Option<Error>,
}

#[derive(Debug)]
pub enum DBErrKind {
    KeyExists,
    CreateError,
    FetchError,
    MissingKey,
    UpdateError,
}

impl fmt::Display for DBErrKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            DBErrKind::KeyExists => "The Key already exists",
            DBErrKind::CreateError => "Failed to create the key",
            DBErrKind::FetchError => "Failed to fetch the data",
            DBErrKind::MissingKey => "The Key doesn't exist",
            DBErrKind::UpdateError => "Failed to update the key",
        };
        write!(f, "{}", printable)
    }
}

#[derive(Fail, Debug)]
#[fail(display = "Error inside the Enclave = ({:?})", err)]
pub struct EnclaveFailError {
    pub err: enigma_types::EnclaveReturn,
    pub status: sgx_status_t,
}

//impl From<enigma_types::EnclaveReturn> for EnclaveFailError {
//    fn from(error: enigma_types::EnclaveReturn) -> Self { Self { err: error } }
//}
