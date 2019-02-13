use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::time;

// general
use web3::futures::Future;
use web3::futures::stream::Stream;
use web3::types::FilterBuilder;

use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::keeper_types_u::EventWrapper;

pub struct EpochProvider {
    contract: Arc<EnigmaContract>,
    last_block_number: Option<AtomicUsize>,
    eid: Arc<AtomicU64>,
}

impl EpochProvider {
    pub fn new(eid: Arc<AtomicU64>, contract: Arc<EnigmaContract>) -> Self {
        EpochProvider { contract, last_block_number: None, eid }
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
    use enigma_tools_u::web3_utils::keeper_types_u::{decode, Log, Receipt};
    use enigma_tools_u::web3_utils::provider_types::{encode, LogWrapper, ReceiptWrapper};
    use enigma_tools_u::web3_utils::w3utils;

    use super::*;

    /// This function is important to enable testing both on the CI server and local.
            /// On the CI Side:
            /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
            /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
            /// The default is set to ganache cli "http://localhost:8545"
    pub fn get_node_url() -> String { env::var("NODE_URL").unwrap_or(String::from("http://localhost:9545")) }
}
