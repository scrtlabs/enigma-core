use ethabi::{Bytes, Address, Event, EventParam, FixedBytes, Hash, ParamType, RawLog, Token, Uint};
use ethabi::token::{LenientTokenizer, Tokenizer};
use sgx_types::*;
use std::string::ToString;
use std::prelude::v1::Box;
use std::vec::Vec;
use std::panic;
use std::convert::From;
use serde_json as ser;
use eth_tools_t::type_wrappers_t::{EventWrapper, Log};
use ethereum_types::{H160, U256};
use common::errors_t::EnclaveError;


#[derive(Debug, Clone)]
pub struct WorkerParams {
    pub block_number: Uint,
    pub workers: Vec<Address>,
    pub balances: Vec<Uint>,
}

impl From<Log> for WorkerParams {
    fn from(log: Log) -> Self {
        println!("Parsing log: {:?}", log);
        let event = EventWrapper::workers_parameterized();
        let raw_log = RawLog{ topics: log.topics, data: log.data };
        //TODO: Probably need TryFrom
        let log = event.0.parse_log(raw_log).unwrap();

        // Ugly deserialization from ABI tokens
        let seed = log.params[0].value.clone().to_uint().unwrap();
        let block_number = log.params[1].value.clone().to_uint().unwrap();
        let workers = log.params[2].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_address().unwrap()).collect::<Vec<H160>>();
        let balances = log.params[3].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_uint().unwrap()).collect::<Vec<U256>>();

        Self { block_number, workers, balances }
    }
}

#[derive(Debug, Clone)]
pub struct Epoch {
    pub seed: U256,
    pub worker_params: Option<WorkerParams>,
}

impl Epoch {
    pub fn set_worker_params(&mut self, params: WorkerParams) {
        self.worker_params = Some(params);
    }

    pub fn get_selected_workers(self, sc_addr: Address) -> Result<Vec<Address>, EnclaveError> {
        // TODO: implement the worker selection algo
        let workers = self.worker_params.unwrap().workers.to_vec();

        Ok(workers)
    }
}

