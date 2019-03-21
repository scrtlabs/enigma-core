use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;

use failure::Error;
use sgx_types::sgx_enclave_id_t;
use structopt::StructOpt;

use boot_network::deploy_scripts;
use boot_network::principal_manager::{self, PrincipalManager, ReportManager, Sampler};
use cli;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use epoch_u::epoch_provider::EpochProvider;
use esgx::general::{ENCLAVE_DIR, storage_dir};
use boot_network::keys_provider_http::{PrincipalHttpServer, StateKeyRequest};
use serde::Deserialize;
use serde_json;

#[logfn(INFO)]
pub fn start(eid: sgx_enclave_id_t) -> Result<(), Error> {
    let opt = cli::options::Opt::from_args();
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
        if opt.deploy {
            unimplemented!("Self-deploy mode not yet implemented. Fix issues with linked libraries in the Enigma contract.");
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

            let eid_safe = Arc::new(eid);
            let epoch_provider = EpochProvider::new(eid_safe, principal.contract.clone())?;
            if opt.reset_epoch_state {
                epoch_provider.reset_epoch_state()?;
            }
            /* step3 : run the principal manager */
            if opt.register {
                match principal.verify_identity_or_register(gas_limit)? {
                    Some(tx) => println!("Registered Principal with tx: {:?}", tx),
                    None => println!("Principal already registered"),
                };
            } else if opt.set_worker_params || !opt.get_state_keys.is_none() {
                let block_number = principal.get_block_number()?;
                if opt.set_worker_params {
                    let tx = epoch_provider.set_worker_params(block_number, gas_limit, principal_config.confirmations as usize)?;
                    println!("The setWorkersParams tx: {:?}", tx);
                } else {
                    let request: StateKeyRequest = serde_json::from_str(&opt.get_state_keys.unwrap())?;
                    let response = PrincipalHttpServer::get_state_keys(Arc::new(epoch_provider), request)?;
                    println!("The getStateKeys response: {}", serde_json::to_string(&response)?);
                }
            } else {
                principal.run(false, gas_limit).unwrap();
            }
            if let Some(t) = join_handle { t.join().unwrap(); }
        }
    }
    Ok(())
}
