use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use failure::Error;
use sgx_types::sgx_enclave_id_t;
use structopt::StructOpt;

use boot_network::deploy_scripts;
use boot_network::epoch_provider::EpochProvider;
use boot_network::principal_manager::{self, ReportManager, PrincipalManager, Sampler};
use cli;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use serde_json;
use esgx::general::{ENCLAVE_DIR, storage_dir};

pub fn start(eid: sgx_enclave_id_t) -> Result<(), Error> {
    let opt = cli::options::Opt::from_args();
    let _config = deploy_scripts::load_config(opt.deploy_config.as_str())?;
    let mut principal_config = PrincipalManager::load_config(opt.principal_config.as_str())?;
    let report_manager = ReportManager::new(principal_config.clone(), eid)?;
    let signing_address = report_manager.get_signing_address()?;

    if opt.info {
        cli::options::print_info(&signing_address);
    } else if opt.sign_address {
        let mut path = storage_dir();
        path.join(ENCLAVE_DIR);
        path.push("principal-sign-addr.txt");
        let mut file = File::create(path.clone())?;
        let prefixed_signing_address = format!("0x{}", signing_address);
        file.write_all(prefixed_signing_address.as_bytes())?;
        println!("Wrote signing address: {:?} in file: {:?}", prefixed_signing_address, path);
    } else {
//        cli::options::print_logo();

        // deploy the contracts Enigma,EnigmaToken (not deployed yet)
        if opt.deploy {
            println!("[Mode:] deploying to default.");
            /* step1 : prepeare the contracts (deploy Enigma,EnigmaToken) */
            // load the config
            // deploy all contracts. (Enigma & EnigmaToken)
//            let enigma_contract = Arc::new(EnigmaContract::deploy_contract(Path::new(&config.enigma_token_contract_path),
//                                                                  Path::new(&config.enigma_contract_path),
//                                                                  &principal_config.url,
//                                                                  Some(&config.account_address), // This means that account no. 0 will be used, we should use the one from the JSON or add an `--account` cli option. or
//                                                                  &sign_key)?);
//
//            /* step2 : build the config of the principal node   */
//            // optional : set time limit for the principal node
//            let ttl = if opt.time_to_live > 0 { Some(opt.time_to_live) } else { None };
//
//            let gas_limit = 5_999_999;
//            let contract_addr = enigma_contract.address();
//            principal_config.set_accounts_address(enigma_contract.account.to_hex());
//            principal_config.set_enigma_contract_address(contract_addr.to_hex());
//            principal_config.max_epochs = ttl;
//
//            println!("Enigma contract deployed: {:?}", enigma_contract.address());
//            let principal: PrincipalManager = PrincipalManager::new_delegated(principal_config, enigma_contract, eid);
//            println!("Connected to the Enigma contract with account: {:?}", principal.get_account_address());
//
//            /* step3 optional - run miner to simulate blocks */
//            let join_handle = if opt.mine > 0 {
//                Some(principal_manager::run_miner(principal.get_account_address(), principal.get_web3(), opt.mine as u64))
//            } else {
//                None
//            };
//
//            /* step4 : run the principal manager */
//            principal.run(gas_limit).unwrap();
//            if let Some(t) = join_handle { t.join().unwrap(); }
            panic!("Self-deploy mode not yet implemented. Fix issues with linked libraries in the Enigma contract.");
            // contracts deployed, just run
        } else {
            println!("[Mode:] run node NO DEPLOY.");
            /* step1 : build the config of the principal node   */
            // optional : set time limit for the principal node
            let contract_address = match opt.contract_address {
                Some(addr) => addr,
                None => principal_config.enigma_contract_address.clone(),
            };
            let enigma_contract = Arc::new(
                EnigmaContract::from_deployed(&contract_address,
                                              Path::new(&principal_config.enigma_contract_path),
                                              Some(&principal_config.account_address),
                                              &principal_config.url,
                )?);

            let ttl = if opt.time_to_live > 0 { Some(opt.time_to_live) } else { None };

            let gas_limit = 5_999_999;
            principal_config.max_epochs = ttl;

            let principal: PrincipalManager = PrincipalManager::new(principal_config.clone(), enigma_contract, report_manager)?;
            println!("Connected to the Enigma contract: {:?} with account: {:?}", &contract_address, principal.get_account_address());

            /* step2 optional - run miner to simulate blocks */
            let join_handle = if opt.mine > 0 {
                Some(principal_manager::run_miner(principal.get_account_address(), principal.get_web3(), opt.mine as u64))
            } else {
                None
            };

            /* step3 : run the principal manager */
            if opt.register {
                match principal.verify_identity_or_register(gas_limit)? {
                    Some(tx) => println!("Registered Principal with tx: {:?}", tx),
                    None => println!("Principal already registered"),
                };
            } else if opt.set_worker_params {
                let block_number = principal.get_block_number()?;
                let eid_safe = Arc::new(AtomicU64::new(eid));
                let epoch_provider = EpochProvider::new(eid_safe, principal.contract.clone())?;
                let tx = epoch_provider.set_worker_params(block_number, gas_limit, principal_config.confirmations as usize)?;
                println!("The setWorkersParams tx: {:?}", tx);
            } else {
                principal.run(gas_limit).unwrap();
            }
            if let Some(t) = join_handle { t.join().unwrap(); }
        }
    }
    Ok(())
}
