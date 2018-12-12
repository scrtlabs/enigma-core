use web3::types::U256;
use web3::types::Address;
use std::collections::HashMap;

pub struct WorkerParameters {
    seed: U256,
    workers: Vec<Address>,
    firstBlockNumber: U256,
}

pub struct PrincipalKeystore {
    keys: HashMap<Address, u8>,
}
