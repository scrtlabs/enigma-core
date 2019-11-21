use enigma_tools_u::web3_utils::w3utils;
use failure::Error;
use rustc_hex::ToHex;
use std::{str, sync::Arc, thread, time};
use web3::{
    contract::{Contract, Options},
    futures::Future,
    transports::Http,
    types::Address,
    Web3,
};

/// TESTING: deploy the dummy contract
fn deploy_dummy_miner(w3: &Web3<Http>, deployer: &str) -> Result<Contract<Http>, Error> {
    // contract path
    let path = "../app/tests/principal_node/contracts/Dummy.json";
    // build deploy params
    let gas_limit: u64 = 5_999_999;
    let poll_interval: u64 = 1;
    let confirmations: usize = 0;
    let (abi, bytecode) = w3utils::load_contract_abi_bytecode(path)?;

    let tx = w3utils::DeployParams::new(deployer, abi, bytecode, gas_limit, poll_interval, confirmations)?;
    // deploy
    let contract = w3utils::deploy_contract(&w3, &tx, ())?;
    Ok(contract)
}

/// TESTING: mimic block creation to test the watch blocks method of the principal node
pub fn forward_blocks(w3: &Arc<Web3<Http>>, interval: u64, deployer: Address) -> Result<(), Error> {
    let contract = deploy_dummy_miner(&w3, &deployer.to_fixed_bytes().to_hex())?;
    println!("deployed dummy contract at address = {:?}", contract.address());
    loop {
        let gas_limit: u64 = 5_999_999;
        let mut options = Options::default();
        options.gas = Some(gas_limit.into());
        // contract.call("mine",(),deployer,options ).wait().expect("error calling mine on miner.");
        let res = contract.call("mine", (), deployer, options).wait();
        match res {
            Ok(_) => println!("\u{2692}"),
            Err(e) => println!("[-] error mining block =>{:?}", e),
        };
        thread::sleep(time::Duration::from_secs(interval));
    }
}
