use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::time;

// general
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::{FilterBuilder, U256, H256};
use failure::Error;

use enigma_tools_u::web3_utils::provider_types::EventWrapper;
use esgx::epoch_keeper_u::set_worker_params;
use enigma_tools_u::web3_utils::enigma_contract::{ContractFuncs, EnigmaContract, ContractQueries};
use std::sync::atomic::Ordering;

pub struct EpochProvider {
    pub contract: Arc<EnigmaContract>,
    pub last_block_number: Option<AtomicUsize>,
    pub eid: Arc<AtomicU64>,
}

impl EpochProvider {
    pub fn new(eid: Arc<AtomicU64>, contract: Arc<EnigmaContract>) -> Self {
        EpochProvider { contract, last_block_number: None, eid }
    }

    pub fn set_worker_params<G: Into<U256>>(&self, block_number: U256, gas_limit: G) -> Result<(H256), Error> {
        let worker_params = self.contract.get_active_workers(block_number)?;
        println!("The active workers: {:?}", worker_params);
        let epoch_seed = set_worker_params(self.eid.load(Ordering::SeqCst), worker_params)?;
        println!("Calling setWorkersParams with EpochSeed: {:?}", epoch_seed);
        let tx = self.contract.set_workers_params(block_number, epoch_seed.seed, epoch_seed.sig, gas_limit)?;
        println!("The setWorkersParams tx: {:?}", tx);
        Ok(tx)
    }

    pub fn filter_worker_params(self: Arc<Self>) {
        let event = EventWrapper::workers_parameterized();
        let event_sig = event.0.signature();
        // Filter for Hello event in our contract
        let filter = FilterBuilder::default()
            .address(vec![self.contract.address()])
            .topics(
                Some(vec![
                    event_sig.into(),
                ]),
                None,
                None,
                None,
            )
            .build();

        let event_future = self.contract.web3.eth_filter()
            .create_logs_filter(filter)
            .then(|filter| {
                filter
                    .unwrap()
                    .stream(time::Duration::from_secs(1))
                    .for_each(|log| {
                        println!("Got WorkerParameterized event log");
                        Ok(())
                    })
            })
            .map_err(|err| eprintln!("Unable to store worker parameters: {:?}", err));
        event_future.wait().unwrap();
    }
}

//////////////////////// TESTS  /////////////////////////////////////////

#[cfg(test)]
mod test {
    use std::env;
    use super::*;

    /// This function is important to enable testing both on the CI server and local.
            /// On the CI Side:
            /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
            /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
            /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:9545")) }
}
