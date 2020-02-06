use thiserror::Error;

use sgx_types::sgx_status_t;

// error while request attestation service
#[derive(Error, Debug)]
#[error("Error while using the attestation service info = ({message:?})")]
pub struct AttestationServiceErr {
    pub message: String,
}

#[derive(Error, Debug)]
#[error("Error while decoding the quote = ({message:?})")]
pub struct QuoteErr {
    pub message: String,
}

#[derive(Error, Debug)]
#[error("Error while decoding the quote = ({message:?})")]
pub struct WasmError {
    pub message: String,
}

#[derive(Error, Debug)]
#[error("Error while using the web3 server = ({message:?})")]
pub struct Web3Error {
    pub message: String,
}

#[derive(Error, Debug)]
#[error("SGX Ecall Failed function: {function:?}, status: {status:?}")]
pub struct SgxError {
    pub status: sgx_status_t,
    pub function: &'static str,
}
