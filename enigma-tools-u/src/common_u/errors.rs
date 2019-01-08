use sgx_types::sgx_status_t;

// error while request attestation service
#[derive(Fail, Debug)]
#[fail(display = "Error while using the attestation service info = ({})", message)]
pub struct AttestationServiceErr {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while decoding the quote = ({})", message)]
pub struct QuoteErr {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while decoding the quote = ({})", message)]
pub struct WasmError {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while using the web3 server = ({})", message)]
pub struct Web3Error {
    pub message: String,
}

#[derive(Fail, Debug)]
#[fail(display = "SGX Ecall Failed function: {}, status: {}", function, status)]
pub struct SgxError {
    pub status: sgx_status_t,
    pub function: &'static str,
}
