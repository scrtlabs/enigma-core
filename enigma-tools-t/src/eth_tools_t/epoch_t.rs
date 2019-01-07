use ethabi::{Address, Event, EventParam, FixedBytes, Hash, ParamType, RawLog, Token, Uint};
use ethabi::token::{LenientTokenizer, Tokenizer};
use sgx_types::*;
use std::string::ToString;
use std::prelude::v1::Box;
use std::vec::Vec;
use std::panic;
use std::convert::TryFrom;
use serde_json as ser;
use eth_tools_t::keeper_types_t::{EventWrapper, Log};
use ethereum_types::{H160, U256};
use common::errors_t::EnclaveError;


#[derive(Debug, Clone)]
pub struct WorkerParams {
    pub block_number: U256,
    pub workers: Vec<Address>,
    pub balances: Vec<U256>,
    pub nonce: U256,
}

impl TryFrom<Log> for WorkerParams {
    type Error = EnclaveError;
    fn try_from(log: Log) -> Result<WorkerParams, EnclaveError> {
        println!("Parsing log: {:?}", log);
        let event = EventWrapper::workers_parameterized();
        let raw_log = RawLog { topics: log.topics, data: log.data };
        let log = match event.0.parse_log(raw_log) {
            Ok(log) => log,
            Err(err) => return Err(EnclaveError::WorkerAuthError { err: format!("Unable to parse the log: {:?}", err) }),
        };
        // Ugly deserialization from ABI tokens
        // TODO: do I really need to clone so much?
        let seed = log.params[0].value.clone().to_uint().unwrap();
        let block_number = log.params[1].value.clone().to_uint().unwrap();
        let workers = log.params[2].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_address().unwrap()).collect::<Vec<H160>>();
        let balances = log.params[3].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_uint().unwrap()).collect::<Vec<U256>>();
        let nonce = log.params[4].value.clone().to_uint().unwrap();

        Ok(Self { block_number, workers, balances, nonce })
    }
}

#[derive(Debug, Clone)]
pub struct Epoch {
    pub seed: U256,
    pub worker_params: Option<WorkerParams>,
    pub preverified_block_hash: Hash,
}

impl Epoch {
    pub fn set_worker_params(&mut self, params: WorkerParams) -> Result<(), EnclaveError> {
        // TODO: what could go wrong here?
        self.worker_params = Some(params);
        Ok(())
    }

    pub fn get_selected_workers(self, sc_addr: Address) -> Result<Vec<Address>, EnclaveError> {
        // TODO: implement the worker selection algo
        let workers = self.worker_params.unwrap().workers.to_vec();

        Ok(workers)
    }
}

