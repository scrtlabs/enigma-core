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

#[cfg(test)]
mod test {
    use esgx::general::init_enclave_wrapper;
    use std::env;

    /// This function is important to enable testing both on the CI server and local.
    /// On the CI Side:
    /// The ethereum network url is being set into env variable 'NODE_URL' and taken from there.
    /// Anyone can modify it by simply doing $export NODE_URL=<some ethereum node url> and then running the tests.
    /// The default is set to ganache cli "http://localhost:8545"
    fn get_node_url() -> String { env::var("NODE_URL").unwrap_or("http://localhost:8545".to_string()) }

    #[test]
    fn test_deploy_enigma_contract_environment() {
        let enclave = init_enclave_wrapper().unwrap();
        let _eid = enclave.geteid();
        // load the config
        //        let deploy_config = "../app/tests/principal_node/contracts/deploy_config.json";
        //        let mut config = deploy_scripts::load_config(deploy_config).unwrap();
        //        // modify to dynamic address
        //        config.set_ethereum_url(get_node_url());
        // deploy all contracts.
        //        let signer_addr = get_signing_address(eid).unwrap();
        //        let _enigma_contract = EnigmaContract::deploy_contract(Path::new(&config.enigma_token_contract_path),
        //                                                               Path::new(&config.enigma_contract_path),
        //                                                               &get_node_url(),
        //                                                               None,
        //                                                               &signer_addr).unwrap();
    }

}
