use failure::Error;
use sgx_types::sgx_enclave_id_t;
use structopt::StructOpt;

use boot_network::deploy_scripts;
use boot_network::principal_manager::{self, PrincipalManager, Sampler};
use cli;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use rustc_hex::ToHex;
use std::path::Path;

pub use esgx::general::ocall_get_home;

pub fn start(eid: sgx_enclave_id_t) -> Result<(), Error> {
    let opt = cli::options::Opt::from_args();
    let config = deploy_scripts::load_config(opt.deploy_config.as_str())?;
    let mut principal_config = PrincipalManager::load_config(opt.principal_config.as_str())?;
    let sign_key = deploy_scripts::get_signing_address(eid)?;

    if opt.info {
        cli::options::print_info(&sign_key);
    } else {
        cli::options::print_logo();

        // deploy the contracts Enigma,EnigmaToken (not deployed yet)
        if opt.deploy {
            println!("[Mode:] deploying to default.");
            /* step1 : prepeare the contracts (deploy Enigma,EnigmaToken) */
            // load the config
            // deploy all contracts. (Enigma & EnigmaToken)
            let enigma_contract = EnigmaContract::deploy_contract(Path::new(&config.enigma_token_contract_path),
                                                                  Path::new(&config.enigma_contract_path),
                                                                  &config.url,
                                                                  None, // This means that account no. 0 will be used, we should use the one from the JSON or add an `--account` cli option. or
                                                                  &sign_key)?;

            /* step2 : build the config of the principal node   */
            // optional : set time limit for the principal node
            let ttl = if opt.time_to_live > 0 { Some(opt.time_to_live) } else { None };

            let gas_limit = 5_999_999;
            let contract_addr = enigma_contract.address();
            principal_config.set_accounts_address(enigma_contract.account.to_hex());
            principal_config.set_enigma_contract_address(contract_addr.to_hex());
            principal_config.max_epochs = ttl;

            let principal: PrincipalManager = PrincipalManager::new_delegated(principal_config, enigma_contract, eid);

            /* step3 optional - run miner to simulate blocks */
            if opt.mine > 0 {
                principal_manager::run_miner(principal.get_account_address(), principal.get_web3(), opt.mine as u64);
            }

            /* step4 : run the principal manager */
            principal.run(gas_limit).unwrap();
        // contracts deployed, just run
        } else {
            println!("[Mode:] run node NO DEPLOY.");

            /* step1 : build the config of the principal node   */
            // optional : set time limit for the principal node

            let enigma_contract = EnigmaContract::from_deployed(&config.account_address,
                                                                Path::new(&config.enigma_contract_path),
                                                                None, // This means that account no. 0 will be used, we should use the one from the JSON or add an `--account` cli option. or
                                                                &config.url)?;

            let ttl = if opt.time_to_live > 0 { Some(opt.time_to_live) } else { None };

            let gas_limit = 5_999_999;
            principal_config.max_epochs = ttl;

            let principal: PrincipalManager = PrincipalManager::new_delegated(principal_config, enigma_contract, eid);

            /* step2 optional - run miner to simulate blocks */
            if opt.mine > 0 {
                principal_manager::run_miner(principal.get_account_address(), principal.get_web3(), opt.mine as u64);
            }

            /* step3 : run the principal manager */
            principal.run(gas_limit).unwrap();
        }
    }
    Ok(())
}
