use std::{thread, time};

use web3::{futures::Future, types::U256};

use controller::km_controller::KMController;

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait EthereumTracker {
    fn epoch_trigger(&self, epoch_size: usize, polling_interval: u64, confirmations: usize);
}

impl EthereumTracker for KMController {
    /// Watches the blocks for new epoch using the epoch size and the previous epoch block number.
    /// For each new epoch, set the worker parameters.
    #[logfn(INFO)]
    fn epoch_trigger(&self, epoch_size: usize, polling_interval: u64, confirmations: usize) {
        loop {
            let block_number = match self.contract.web3.eth().block_number().wait() {
                Ok(block_number) => block_number,
                Err(err) => {
                    error!("Unable to fetch block number: {:?}", err);
                    thread::sleep(time::Duration::from_secs(polling_interval));
                    continue;
                }
            };
            let curr_block = block_number.low_u64() as usize;
            let prev_block = match self.epoch_verifier.last(true) {
                Ok(state) => state.confirmed_state.unwrap().ether_block_number,
                Err(_) => U256::zero(),
            };
            let prev_block_ref = prev_block.low_u64() as usize;
            if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                self
                    .set_worker_params(block_number, confirmations)
                    .expect("Unable to set worker params. Please recover manually.");
            }
            thread::sleep(time::Duration::from_secs(polling_interval));
        }
    }
}
