use std::sync::Arc;
use std::{fs::File, io::prelude::*, path::Path};

use failure::Error;
use sgx_types::sgx_enclave_id_t;
use structopt::StructOpt;
use rustc_hex::{FromHex, ToHex};
use crossbeam_utils::thread;

use controller::{
    km_http_server::KMHttpServer,
    km_utils::{
        KMConfig,
        SgxEthereumSigner,
        PrivateKeyEthereumSigner
    },
};
use common_u::custom_errors::{ControllerError, EnclaveError, VerifierError, ConfigError};
use esgx::general::ENCLAVE_DIR;
use esgx::equote;
use controller;
use enigma_crypto::EcdsaSign;
use enigma_tools_u::{esgx::general::storage_dir, web3_utils::enigma_contract::EnigmaContract};
use controller::km_controller::KMController;
use epochs::epoch_trigger::EthereumTracker;

pub fn create_signer(eid: sgx_enclave_id_t, with_private_key: bool, private_key: &[u8]) -> Box<dyn EcdsaSign + Send + Sync> {
    if with_private_key {
        let mut pk_32 = [0u8; 32];
        pk_32.copy_from_slice(private_key);
        let signer = Box::new(PrivateKeyEthereumSigner::new(pk_32)) as Box<dyn EcdsaSign + Send + Sync>;
        signer
    } else {
        let signer = Box::new(SgxEthereumSigner::new(eid)) as Box<dyn EcdsaSign + Send + Sync>;
        signer
    }
}

fn get_signing_address(eid: sgx_enclave_id_t) -> Result<String, EnclaveError> {
    Ok(equote::get_register_signing_address(eid).or(Err(EnclaveError::UnDetailedEnclaveErr))?.to_hex())
}

fn get_ethereum_address(eid: sgx_enclave_id_t, config: KMConfig) -> Result<String, EnclaveError> {
    if config.with_private_key {
        return Ok(config.account_address.clone());
    }
    Ok(equote::get_ethereum_address(eid).or(Err(EnclaveError::UnDetailedEnclaveErr))?.to_hex())
}

#[logfn(INFO)]
pub fn start(eid: sgx_enclave_id_t) -> Result<(), ControllerError> {
    let opt = controller::options::Opt::from_args();
    let config = KMConfig::load_config(opt.principal_config.as_str())?;

    let mut path = storage_dir(ENCLAVE_DIR).map_err(|_| ControllerError::VerifierError(VerifierError::CreateErr))?;
    let ethereum_address = get_ethereum_address(eid, config.clone()).map_err(|e| ControllerError::EnclaveError(e))?;

    if opt.sign_address {
        path.push("principal-sign-addr.txt");
        let mut file = File::create(&path).map_err(|_| ControllerError::VerifierError(VerifierError::CreateErr))?;

        let signing_address = get_signing_address(eid).map_err(|e| ControllerError::EnclaveError(e))?;
        let prefixed_signing_address = format!("0x{}", signing_address);

        file.write_all(prefixed_signing_address.as_bytes()).map_err(|_| ControllerError::VerifierError(VerifierError::WriteErr))?;
        println!("Wrote signing address: {:?} in file: {:?}", prefixed_signing_address, path);

        path.pop();
        path.push("ethereum-account-addr.txt");
        let mut file = File::create(&path).map_err(|_| ControllerError::VerifierError(VerifierError::CreateErr))?;

        let prefixed_ethereum_address = format!("0x{}", ethereum_address);

        file.write_all(prefixed_ethereum_address.as_bytes()).map_err(|_| ControllerError::VerifierError(VerifierError::WriteErr))?;
        println!("Wrote ethereum address: {:?} in file: {:?}", prefixed_ethereum_address, path);

    } else {
        let private_key = config.private_key.from_hex().map_err(|_| ConfigError::Parsing)?;
        let ethereum_signer = create_signer(eid, config.with_private_key, &private_key);

        let contract_address = opt.contract_address.unwrap_or_else(|| config.enigma_contract_address.clone());
        let enigma_contract = EnigmaContract::from_deployed(
            &contract_address,
            Path::new(&config.enigma_contract_path),
            Some(&ethereum_address),
            config.chain_id,
            &config.url,
            ethereum_signer,
        ).map_err(|e| ControllerError::GenericError(e))?;

        let controller = KMController::new(eid, path.clone(), enigma_contract, config)?;
        println!("Connected to the Enigma contract: {:?} with account: {:?}", &contract_address, controller.contract.get_km_account());

        run(opt.reset_epoch_state, controller)?;
    }
    Ok(())
}

#[logfn(INFO)]
fn run(reset_epoch: bool, controller: KMController) -> Result<(), ControllerError> {
    controller.verify_identity_or_register()?;
    if reset_epoch {
        controller.epoch_verifier.reset().map_err(|e| ControllerError::VerifierError(e))?;
    }

    let port = controller.config.http_port;
    let controller1 = Arc::new(controller);
    let controller2 = Arc::clone(&controller1);
    let _ = thread::scope(|s| {
        s.spawn(|_| {
            let server = KMHttpServer::new(controller1, port);
            server.start();
        });
        s.spawn(|_|{
            controller2.epoch_trigger(
                controller2.config.epoch_size,
                controller2.config.polling_interval,
                 controller2.config.confirmations as usize,
            );
        });
    });
    Ok(())
}
