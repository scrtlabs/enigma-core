use ethabi::{Bytes, Address, decode, encode, Event, EventParam, FixedBytes, Hash, Log, ParamType, RawLog, Token, Uint};
use ethabi::token::{LenientTokenizer, Tokenizer};
use sgx_types::*;
use std::string::ToString;
use std::prelude::v1::Box;
use std::vec::Vec;
use std::panic;
use common::errors_t::EnclaveError;
use serde_json as ser;


#[derive(Debug, Clone)]
pub struct WorkerParams {
    pub block_number: Uint,
    pub workers: Vec<Address>,
    pub balances: Vec<Uint>,
}

// TODO: Write serializer/deserializer using the Token module to encode ABI types to bytes
#[derive(Debug, Clone)]
pub struct Epoch {
    pub seed: Uint,
    pub worker_params: Option<WorkerParams>,
}

impl Epoch {
    pub fn set_worker_params(&mut self, raw_log: RawLog) -> Result<(), EnclaveError> {
        println!("Parsing raw log: {:?}", raw_log);
        let event = Event {
            name: "WorkersParameterized".to_string(),
            inputs: vec![EventParam {
                name: "seed".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "blockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            }, EventParam {
                name: "workers".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                indexed: false,
            }, EventParam {
                name: "balances".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                indexed: false,
            }],
            anonymous: false,
        };
        let log = match event.parse_log(raw_log) {
            Ok(log) => {
                println!("the decoded log: {:?}", log);
                log
            }
            Err(err) => {
                return Err(EnclaveError::WorkerAuthError {
                    err: format!("Unable to parse the log: {:?}", err),
                });
            }
        };
        let block_number = panic::catch_unwind(|| {
            log.params[1].value.clone().to_uint().unwrap()
        }).expect("Unable to cast block number");
        let workers = panic::catch_unwind(|| {
            log.params[2].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_address().unwrap()).collect()
        }).expect("Unable to cast workers.");
        let balances = panic::catch_unwind(|| {
            log.params[3].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_uint().unwrap()).collect()
        }).expect("Unable to cast balances.");

        let worker_params = WorkerParams { block_number, workers, balances };
        self.worker_params = Some(worker_params);
        Ok(())
    }

    pub fn get_selected_workers(self, sc_addr: Address) -> Result<Vec<Address>, EnclaveError> {
        // TODO: implement the worker selection algo
        let workers = self.worker_params.unwrap().workers.to_vec();

        Ok(workers)
    }
}
