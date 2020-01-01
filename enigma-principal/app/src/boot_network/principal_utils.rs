use std::{sync::Arc, thread, time};

use web3::{futures::Future, types::U256};

use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use epoch_u::epoch_provider::EpochProvider;

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
    fn watch_blocks<G: Into<U256>>(
        &self,
        epoch_size: usize,
        polling_interval: u64,
        epoch_provider: Arc<EpochProvider>,
        gas_limit: G,
        confirmations: usize,
        max_epochs: Option<usize>
    );
}

impl Principal for EnigmaContract {
    /// Watches the blocks for new epoch using the epoch size and the previous epoch block number.
    /// For each new epoch, set the worker parameters.
    #[logfn(INFO)]
    fn watch_blocks<G: Into<U256>>(
        &self,
        epoch_size: usize,
        polling_interval: u64,
        epoch_provider: Arc<EpochProvider>,
        gas_limit: G,
        confirmations: usize,
        max_epochs: Option<usize>
    ) {
        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        loop {
            let block_number = match self.web3.eth().block_number().wait() {
                Ok(block_number) => block_number,
                Err(err) => {
                    error!("Unable to fetch block number: {:?}", err);
                    thread::sleep(time::Duration::from_secs(polling_interval));
                    continue;
                }
            };
            let curr_block = block_number.low_u64() as usize;
            let prev_block = match epoch_provider.epoch_state_manager.last(true) {
                Ok(state) => state.confirmed_state.unwrap().ether_block_number,
                Err(_) => U256::zero(),
            };
            let prev_block_ref = prev_block.low_u64() as usize;
            trace!("Blocks @ previous: {}, current: {}, next: {}", prev_block_ref, curr_block, (prev_block_ref + epoch_size));
            if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                trace!("New epoch for block number {} [epoch size {}]", curr_block, epoch_size);
                epoch_provider
                    .set_worker_params(block_number, gas_limit, confirmations)
                    .expect("Unable to set worker params. Please recover manually.");
            } else {
                trace!("Epoch still active");
            }
            thread::sleep(time::Duration::from_secs(polling_interval));
            if max_epochs != 0 {
                // in order to avoid overflow - don't increment when max_epochs is 0
                epoch_counter += 1;
                if epoch_counter == max_epochs {
                    error!("reached max_epochs {} , stopping.", max_epochs);
                    break;
                }
            }
        }
    }
}
