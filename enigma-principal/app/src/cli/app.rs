// general modules
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use structopt::StructOpt;
use std::thread;
// enigma modules 
pub use esgx::general::ocall_get_home;
use boot_network::principal_utils::EmittParams;
use boot_network::principal_manager::{PrincipalConfig,Sampler,PrincipalManager};
use boot_network::deploy_scripts;
use enigma_tools_u::web3_utils::w3utils;
use boot_network::principal_manager;
use esgx::equote;
use cli;



pub fn start(eid : sgx_enclave_id_t){
    
    let opt = cli::options::Opt::from_args();
    let config = opt.deploy_config.as_str();
    let principal_config = opt.principal_config.as_str();

    match opt.info {
        // show info only
        true =>{

            let sign_key = deploy_scripts::get_signing_address(eid).expect("cannot load signing key");
            cli::options::print_info(&sign_key);

        },
        // run the node 
        false =>{

            cli::options::print_logo();

            match opt.deploy{
                // deploy the contracts Enigma,EnigmaToken (not deployed yet)
                true =>{

                        println!("[Mode:] deploying to default.");
                        /* step1 : prepeare the contracts (deploy Enigma,EnigmaToken) */

                        // load the config 
                        let mut config = deploy_scripts::load_config(config);
                        let url = config.URL.clone();
                        // get dynamic eth addrress
                        let accounts = w3utils::get_accounts(config.URL.clone().as_str()).unwrap();
                        let deployer : String = w3utils::address_to_string_addr(&accounts[0]);
                        // modify to dynamic address
                        config.set_accounts_address(deployer);
                        // deploy all contracts. (Enigma & EnigmaToken)
                        let (enigma_contract, enigma_token ) = deploy_scripts::deploy_base_contracts_delegated
                        (
                            eid, 
                            config, 
                            None
                        )
                        .expect("cannot deploy Enigma,EnigmaToken");

                        /* step2 : build the config of the principal node   */

                        // optional : set time limit for the principal node 
                        let mut ttl = None;
                        if opt.time_to_live > 0{
                            ttl = Some(opt.time_to_live);
                        }
                        let mut params : EmittParams = EmittParams{ 
                            eid : eid, 
                            gas_limit : String::from("5999999"),
                            max_epochs : ttl, 
                            ..Default::default()
                        };

                        let mut the_config = PrincipalManager::load_config(principal_config);
                        let contract_addr : String = w3utils::address_to_string_addr(&enigma_contract.address());
                        let deployer = w3utils::address_to_string_addr(&accounts[0]);
                        the_config.set_accounts_address(deployer);
                        the_config.set_enigma_contract_address(contract_addr.clone());
                        
                        /* step3 optional - run miner to simulate blocks */
                        
                        if opt.mine >0 {
                            cli::options::run_miner(url, &accounts, opt.mine);
                        }

                        /* step4 : run the principal manager */

                        let principal : PrincipalManager = PrincipalManager::new_delegated(principal_config, params, the_config);
                        principal.run().unwrap();

                },
                // contracts deployed, just run 
                false =>{
                    
                    println!("[Mode:] run node NO DEPLOY.");

                     /* step1 : build the config of the principal node   */

                    // optional : set time limit for the principal node 
                    let mut ttl = None;
                    if opt.time_to_live > 0{
                        ttl = Some(opt.time_to_live);
                    }
                    let mut params : EmittParams = EmittParams{ 
                        eid : eid, 
                        gas_limit : String::from("5999999"),
                        max_epochs : ttl, 
                        ..Default::default()
                    };
                    
                    let principal : PrincipalManager = PrincipalManager::new(principal_config, params, None);
            
                    /* step2 optional - run miner to simulate blocks */
                    
                    if opt.mine >0 {
                        cli::options::run_miner
                        (
                            principal.get_network_url(), 
                            &vec![principal.get_account_address().unwrap()], 
                            opt.mine
                        );
                    }

                    /* step3 : run the principal manager */
                    
                    principal.run().unwrap();
                }
            }
        },
    };

}