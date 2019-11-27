#![allow(dead_code)]
use sgx_types::*;
use std::fmt;
use failure::Error;

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

// error while request attestation service
#[derive(Fail, Debug)]
#[fail(display = "Error while using the attestation service info = ({})", message)]
pub struct AttestationServiceErr {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while parsing the p2p messages, command: {}, error: {}", cmd, msg)]
pub struct P2PErr {
    pub cmd: String,
    pub msg: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while trying to {}, Because: {}", command, kind)]
pub struct DBErr {
    pub command: String,
    pub kind: DBErrKind,
}

/// This method is called by all functions removing data from the DB. checks if the error
/// is of DBErr type, is so, the error is a missing key error
/// (The only option for an error of that type in the delete methods)
/// which is considered as a success for this matter
pub fn is_db_err_type(e: Error) -> Result<DBErr, Error> {
    e.downcast::<DBErr>()
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
