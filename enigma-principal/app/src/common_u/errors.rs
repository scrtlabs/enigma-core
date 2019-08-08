#![allow(dead_code, unused_assignments, unused_variables)]

use sgx_types::*;

pub const JSON_RPC_ERROR_WORKER_NOT_AUTHORIZED: i64  =-32001;
pub const JSON_RPC_ERROR_ILLEGAL_STATE: i64  =-32002;

// error while requesting to produce a quote (registration)
#[derive(Fail, Debug)]
#[fail(display = "Error while producing a quote sgx_status = {}. info = ({})", status, message)]
pub struct ProduceQuoteErr {
    pub status: sgx_status_t,
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
#[fail(display = "Error inside the Enclave = ({:?})", err)]
pub struct EnclaveFailError {
    pub err: enigma_types::EnclaveReturn,
    pub status: sgx_status_t,
}

#[derive(Fail, Debug)]
#[fail(display = "Operation not allowed while the EpochState is transitioning. Current state = {}", current_state)]
pub struct EpochStateTransitionErr {
    pub current_state: String
}

#[derive(Fail, Debug)]
#[fail(display = "info = ({})", message)]
pub struct EpochStateIOErr {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "The EpochState is undefined")]
pub struct EpochStateUndefinedErr {}

#[derive(Fail, Debug)]
#[fail(display = "Value error in JSON-RPC request: {}. info = ({})", request, message)]
pub struct RequestValueErr {
    pub request: String,
    pub message: String,
}
