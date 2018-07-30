#![allow(dead_code,unused_assignments,unused_variables)]
use sgx_types::*;

// error while requesting to produce a quote (registration)
#[derive(Fail, Debug)]
#[fail(display = "Error while producing a quote sgx_status = {}. info = ({})", status, message)]
pub struct ProduceQuoteErr {
    pub status : sgx_status_t,
    pub message : String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while decoding the quote = ({})", message)]
pub struct QuoteErr{
    pub message : String,
}

// error while requesting the public signing key (the registration key)
#[derive(Fail, Debug)]
#[fail(display = "Error while retrieving the registration signing public key sgx_status = {}. info = ({})", status, message)]
pub struct GetRegisterKeyErr{
    pub status : sgx_status_t,
    pub message : String,
}

// error while requesting execevm computation
#[derive(Fail, Debug)]
#[fail(display = "Error doing execevm command sgx_status = {}. info = ({})", status, message)]
pub struct ExecEvmErr{
    pub status : sgx_status_t,
    pub message : String,
}

// error while request attestation service 
#[derive(Fail, Debug)]
#[fail(display = "Error while using the attestation service info = ({})", message)]
pub struct AttestationServiceErr{
    pub message : String,
}



