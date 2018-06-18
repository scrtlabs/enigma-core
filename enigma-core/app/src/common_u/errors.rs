use failure::Error;
use failure::err_msg;

use sgx_types::*;

#[derive(Fail, Debug)]
#[fail(display = "Error while producing a quote sgx_status = {}. info = ({})", status, message)]
pub struct ProduceQuoteErr {
    pub status : sgx_status_t,
    pub message : String,
}

