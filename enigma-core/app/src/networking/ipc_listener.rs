use crate::networking::messages::*;
use crate::db::DB;
use futures::{Future, Stream};
use sgx_types::sgx_enclave_id_t;
use std::sync::Arc;
use tokio_zmq::prelude::*;
use tokio_zmq::{Error, Multipart, Rep};

pub struct IpcListener {
    _context: Arc<zmq::Context>,
    rep_future: Box<dyn Future<Item = Rep, Error = Error>>,
}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let _context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(_context.clone()).bind(conn_str).build();
        debug!("Binded to socket: {}", conn_str);
        IpcListener { _context, rep_future }
    }

    pub fn run<F>(self, f: F) -> impl Future<Item = (), Error = Error>
    where F: FnMut(Multipart) -> Multipart {
        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f).forward(sink).map(|(_stream, _sink)| ())
        })
    }
}

pub fn handle_message(db: &mut DB, request: Multipart, spid: &str, eid: sgx_enclave_id_t, retries: u32) -> Multipart {
    let mut responses = Multipart::new();
    for msg in request {
        let msg: IpcMessageRequest = msg.into();
        let id = msg.id.clone();
        let response_msg = match msg.request {
            IpcRequest::GetRegistrationParams => handling::get_registration_params(eid, spid, retries),
            IpcRequest::GetTip { input } => handling::get_tip(db, &input),
            IpcRequest::GetTips { input } => handling::get_tips(db, &input),
            IpcRequest::GetAllTips => handling::get_all_tips(db),
            IpcRequest::GetAllAddrs => handling::get_all_addrs(db),
            IpcRequest::GetDelta { input } => handling::get_delta(db, input),
            IpcRequest::GetDeltas { input } => handling::get_deltas(db, &input),
            IpcRequest::GetContract { input } => handling::get_contract(db, &input),
            IpcRequest::UpdateNewContract { address, bytecode } => handling::update_new_contract(db, address, &bytecode),
            IpcRequest::UpdateNewContractOnDeployment { address, bytecode, delta } => handling::update_new_contract_on_deployment(db, address, &bytecode, delta),
            IpcRequest::RemoveContract {address } => handling::remove_contract(db, address),
            IpcRequest::UpdateDeltas { deltas } => handling::update_deltas(db, deltas),
            IpcRequest::RemoveDeltas { input } => handling::remove_deltas(db, input),
            IpcRequest::NewTaskEncryptionKey { user_pubkey } => handling::get_dh_user_key( &user_pubkey, eid),
            IpcRequest::DeploySecretContract { input } => handling::deploy_contract(db, input, eid),
            IpcRequest::ComputeTask { input } => handling::compute_task(db, input, eid),
            IpcRequest::GetPTTRequest => handling::get_ptt_req(eid),
            IpcRequest::PTTResponse { input } => handling::ptt_response(db, &input, eid),
        };
        let msg = IpcMessageResponse::from_response(response_msg.unwrap_or_error(), id);
        responses.push_back(msg.into());
    }
    responses
}


// TODO: Make sure that every ? that doesn't require responding with a empty Message is replaced with an appropriate handling
pub(self) mod handling {
    #![allow(clippy::needless_pass_by_value)]
    use crate::common_u::errors::P2PErr;
    use crate::db::{CRUDInterface, DeltaKey, P2PCalls, Stype, DB};
    use crate::km_u;
    use crate::networking::messages::*;
    use crate::esgx::equote;
    use crate::wasm_u::*;
    use enigma_crypto::hash::Keccak256;
    use enigma_tools_u::esgx::equote as equote_tools;
    use enigma_tools_u::attestation_service::{service::AttestationService, constants::ATTESTATION_SERVICE_URL};
    use enigma_types::ContractAddress;
    use failure::Error;
    use hex::{FromHex, ToHex};
    use rmp_serde::Deserializer;
    use serde::Deserialize;
    use serde_json::Value;
    use sgx_types::sgx_enclave_id_t;
    use std::str;
    use common_u::errors;

    type ResponseResult = Result<IpcResponse, Error>;

    static DEPLOYMENT_VALS_LEN: usize = 2;
    static FAILED_STATE: i64 = -1;

    impl Into<IpcResponse> for WasmTaskFailure{
        fn into(self) -> IpcResponse {
            let result = IpcResults::FailedTask {
                used_gas: self.used_gas,
                output: self.output.to_hex(),
                signature: self.signature.to_hex(),
            };
            IpcResponse::FailedTask { result }
        }
    }

    impl WasmTaskResult {
        pub fn into_execute_response(self) -> IpcResponse {
            let result = IpcResults::ComputeResult {
                used_gas: self.used_gas,
                output: self.output.to_hex(),
                delta: self.delta.into(),
                ethereum_address: self.eth_contract_addr.to_hex(),
                ethereum_payload: self.eth_payload.to_hex(),
                signature: self.signature.to_hex(),
            };
            IpcResponse::ComputeTask { result }
        }

        pub fn into_deploy_response(self, bytecode: &[u8]) -> IpcResponse {
            let result = IpcResults::DeployResult {
                pre_code_hash: bytecode.keccak256().to_hex(),
                used_gas: self.used_gas,
                output: self.output.to_hex(), // TODO: Return output
                delta: self.delta.into(),
                ethereum_address: self.eth_contract_addr.to_hex(),
                ethereum_payload: self.eth_payload.to_hex(),
                signature: self.signature.to_hex(),
            };
            IpcResponse::DeploySecretContract { result }
        }
    }

    #[logfn(TRACE)]
    pub fn get_registration_params(eid: sgx_enclave_id_t, spid: &str, retries: u32) -> ResponseResult {
        let sigining_key = equote::get_register_signing_address(eid)?;

        let enc_quote = equote_tools::retry_quote(eid, spid, 18)?;

        // *Important* `option_env!()` runs on *Compile* time.
        // This means that if you want Simulation mode you need to run `export SGX_MODE=SW` Before compiling.
        let (signature, report_hex) = if option_env!("SGX_MODE").unwrap_or_default() == "SW" { // Simulation Mode
            let report =  enc_quote.as_bytes().to_hex();
            let sig = String::new();
            (sig, report)
        } else { // Hardware Mode
            let service: AttestationService = AttestationService::new_with_retries(ATTESTATION_SERVICE_URL, retries);
            let response = service.get_report(enc_quote)?;
            let report = response.result.report_string.as_bytes().to_hex();
            let sig = response.result.signature;
            (sig, report)
        };

        let result = IpcResults::RegistrationParams { signing_key: sigining_key.to_hex(), report: report_hex, signature };

        Ok(IpcResponse::GetRegistrationParams { result })
    }

    #[logfn(TRACE)]
    pub fn get_tip(db: &DB, input: &str) -> ResponseResult {
        let address = ContractAddress::from_hex(&input)?;
        let (tip_key, tip_data) = db.get_tip::<DeltaKey>(&address)?;

        let key = tip_key.key_type.unwrap_delta();
        let delta = IpcDelta { contract_address: None, key, data: Some(tip_data) };
        Ok(IpcResponse::GetTip { result: delta })
    }

    #[logfn(TRACE)]
    pub fn get_tips(db: &DB, input: &[String]) -> ResponseResult {
        let mut tips_results = Vec::with_capacity(input.len());
        let addresses : Vec<ContractAddress> = input.iter().map(|data| ContractAddress::from_hex(&data).unwrap()).collect();
        let tips = db.get_tips::<DeltaKey>(&addresses)?;
        for (key, data) in tips {
            let delta = IpcDelta::from_delta_key(key, &data)?;
            tips_results.push(delta);
        }
        Ok(IpcResponse::GetTips { result: IpcResults::Tips(tips_results) })
    }

    #[logfn(TRACE)]
    pub fn get_all_tips(db: &DB) -> ResponseResult {
        let tips = db.get_all_tips::<DeltaKey>().unwrap_or_default();
        let mut tips_results = Vec::with_capacity(tips.len());
        for (key, data) in tips {
            let delta = IpcDelta::from_delta_key(key, &data)?;
            tips_results.push(delta);
        }
        Ok(IpcResponse::GetAllTips { result: IpcResults::Tips(tips_results) })
    }

    #[logfn(TRACE)]
    pub fn get_all_addrs(db: &DB) -> ResponseResult {
        let addresses: Vec<String> = db.get_all_addresses().unwrap_or_default().iter().map(|addr| addr.to_hex()).collect();
        Ok(IpcResponse::GetAllAddrs { result: IpcResults::Addresses(addresses) })
    }

    #[logfn(TRACE)]
    pub fn get_delta(db: &DB, input: IpcDelta) -> ResponseResult {
        let address = input.contract_address.ok_or(P2PErr { cmd: "GetDelta".to_string(), msg: "Address Missing".to_string() })?;
        let address = ContractAddress::from_hex(&address)?;
        let delta_key = DeltaKey::new(address, Stype::Delta(input.key));
        let delta = db.get_delta(delta_key)?;
        Ok(IpcResponse::GetDelta { result: IpcResults::Delta(delta.to_hex()) })
    }

    #[logfn(TRACE)]
    pub fn get_deltas(db: &DB, input: &[IpcDeltasRange]) -> ResponseResult {
        let mut results = Vec::with_capacity(input.len());
        for data in input {
            let address = ContractAddress::from_hex(&data.address)?;
            let from = DeltaKey::new(address, Stype::Delta(data.from));
            let to = DeltaKey::new(address, Stype::Delta(data.to));

            let db_res = db.get_deltas(from, to)?;
            if db_res.is_none() {
                results.push(IpcDelta::default());
                continue; // TODO: Check if this handling makes any sense.
            }
            for (key, data) in db_res.unwrap() {
                let delta = IpcDelta::from_delta_key(key, &data)?;
                results.push(delta);
            }
        }

        Ok(IpcResponse::GetDeltas { result: IpcResults::Deltas(results) })
    }

    #[logfn(TRACE)]
    pub fn get_contract(db: &DB, input: &str) -> ResponseResult {
        let address = ContractAddress::from_hex(&input)?;
        let data = db.get_contract(address).unwrap_or_default();
        Ok(IpcResponse::GetContract { result: IpcResults::GetContract{address: address.to_hex(), bytecode: data} })
    }

    #[logfn(TRACE)]
    pub fn update_new_contract(db: &mut DB, address: String, bytecode: &[u8]) -> ResponseResult {
        let address_arr = ContractAddress::from_hex(&address)?;
        let delta_key = DeltaKey::new(address_arr, Stype::ByteCode);
        db.force_update(&delta_key, bytecode)?;
        Ok(IpcResponse::UpdateNewContract { address, result: IpcResults::Status(Status::Passed) })
    }

    #[logfn(TRACE)]
    pub fn update_new_contract_on_deployment(db: &mut DB, address: String, bytecode: &str, delta: IpcDelta) -> ResponseResult {
        let mut tuples = Vec::with_capacity(DEPLOYMENT_VALS_LEN);
        let address_arr = ContractAddress::from_hex(&address)?;

        let bytecode = bytecode.from_hex()?;
        let bytecode_delta_key = DeltaKey::new(address_arr, Stype::ByteCode);
        tuples.push((bytecode_delta_key, &bytecode));

        let data = delta.data.ok_or(P2PErr { cmd: "UpdateNewContractOnDeployment".to_string(), msg: "Delta Data Missing".to_string() })?;
        let delta_key = DeltaKey::new(address_arr, Stype::Delta(delta.key));
        tuples.push((delta_key, &data));

        let results = db.insert_tuples(&tuples);
        let mut status = Status::Passed;
        if results.into_iter().any(| result | result.is_err()) {
            status = Status::Failed;
        }
        // since a new delta and bytecode were added, the state is no longer updated
        db.update_state_status(false);
        let result = IpcResults::Status(status);
        Ok(IpcResponse::UpdateNewContractOnDeployment { address, result })
    }

    #[logfn(TRACE)]
    pub fn remove_contract(db: &mut DB, address: String) -> ResponseResult {
        let addr_arr = ContractAddress::from_hex(&address)?;
        // the key_type of dk is irrelevant since we are removing all the contract data
        let dk = DeltaKey::new(addr_arr, Stype::ByteCode);
        let result = match db.delete_contract(&dk) {
            Ok(_) => IpcResults::Status(Status::Passed),
            Err(e) => {
                match errors::is_db_err_type(e) {
                    Ok(_) => IpcResults::Status(Status::Passed),
                    Err(_) => IpcResults::Status(Status::Failed),
                }
            },
        };
        // no need to update the state_updated flag since the whole contract content does not exist
        Ok( IpcResponse::RemoveContract { address, result } )
    }

    #[logfn(TRACE)]
    pub fn update_deltas(db: &mut DB, deltas: Vec<IpcDelta>) -> ResponseResult {
        let mut tuples = Vec::with_capacity(deltas.len());

        for delta in deltas.into_iter() {
            let address = delta.contract_address.ok_or(P2PErr { cmd: "UpdateDeltas".to_string(), msg: "Address Missing".to_string() })?;
            let address = ContractAddress::from_hex(&address)?;
            let data =
                delta.data.ok_or(P2PErr { cmd: "UpdateDeltas".to_string(), msg: "Delta Data Missing".to_string() })?;
            let delta_key = DeltaKey::new(address, Stype::Delta(delta.key));
            tuples.push((delta_key, data));
        }
        let results = db.insert_tuples(&tuples);
        let mut errors = Vec::with_capacity(tuples.len());
        let mut overall_status = Status::Passed;
        for ((deltakey, _), res) in tuples.into_iter().zip(results.into_iter()) {
            let status = if res.is_err() {
                overall_status = Status::Failed;
                Status::Failed
            } else {
                Status::Passed
            };
            let key = Some(deltakey.key_type.unwrap_delta() as i64);
            let address = deltakey.contract_address.to_hex();
            let delta = IpcStatusResult { address, key, status };
            errors.push(delta);
        }
        // since a new delta was added the state is no longer updated
        db.update_state_status(false);
        let result = IpcResults::DeltasResult { status: overall_status, errors };
        Ok(IpcResponse::UpdateDeltas {result})
    }

    fn delete_data_from_db(db: &mut DB, addr: &str, key_type: Stype) -> Result<IpcResults, Error> {
        let addr_arr = ContractAddress::from_hex(addr)?;
        let dk = DeltaKey::new(addr_arr, key_type);
        match db.delete(&dk) {
            Ok(_) => Ok(IpcResults::Status(Status::Passed)),
            Err(e) => {
                match errors::is_db_err_type(e) {
                    Ok(_) =>  Ok(IpcResults::Status(Status::Passed)),
                    Err(_) => Ok(IpcResults::Status(Status::Failed)),
                }
            },
        }
    }

    #[logfn(TRACE)]
    pub fn remove_deltas(db: &mut DB, input: Vec<IpcDeltasRange>) -> ResponseResult {
        let mut errors = Vec::new();
        let mut overall_status = Status::Passed;
        for addr_deltas in input {
            for key in addr_deltas.from..addr_deltas.to {
                let delta_res = delete_data_from_db(db,&addr_deltas.address.clone(), Stype::Delta(key))?;
                if let IpcResults::Status(Status::Failed) = delta_res {
                    let failed_delta = IpcStatusResult { address: addr_deltas.address.clone() , key: Some(key as i64), status: Status::Failed };
                    errors.push(failed_delta);
                    overall_status = Status::Failed;
                }
            }
            let status_res = delete_data_from_db(db,&addr_deltas.address, Stype::State)?;
            if let IpcResults::Status(Status::Failed) = status_res {
                let failed_delta = IpcStatusResult { address: addr_deltas.address.clone() , key: Some(FAILED_STATE), status: Status::Failed };
                errors.push(failed_delta);
                overall_status = Status::Failed;
            }
        }
        db.update_state_status(false);
        let result = IpcResults::DeltasResult { status: overall_status, errors };
        Ok(IpcResponse::RemoveDeltas {result})
    }

    #[logfn(TRACE)]
    pub fn get_dh_user_key(_user_pubkey: &str, eid: sgx_enclave_id_t) -> ResponseResult {
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&_user_pubkey.from_hex().unwrap());

        let (msg, sig) = km_u::get_user_key(eid, &user_pubkey)?;

        let mut des = Deserializer::new(&msg[..]);
        let res: Value = Deserialize::deserialize(&mut des).unwrap();
        let pubkey = serde_json::from_value::<Vec<u8>>(res["pubkey"].clone())?;

        let result = IpcResults::DHKey {dh_key: pubkey.to_hex(), sig: sig.to_hex() };

        Ok(IpcResponse::NewTaskEncryptionKey {result})
    }

    #[logfn(TRACE)]
    pub fn get_ptt_req(eid: sgx_enclave_id_t) -> ResponseResult {
        let (data, sig) = km_u::ptt_req(eid)?;
        let result = IpcResults::Request { request: data.to_hex(), sig: sig.to_hex() };

        Ok(IpcResponse::GetPTTRequest {result})
    }

    #[logfn(TRACE)]
    pub fn ptt_response(db: &mut DB, response: &PrincipalResponse, eid: sgx_enclave_id_t) -> ResponseResult {
        let msg = response.response.from_hex()?;
        km_u::ptt_res(eid, &msg)?;
        let res = km_u::ptt_build_state(db, eid)?;
        db.update_state_status(true);
        let result: Vec<_> = res
            .into_iter()
            .map(|a| IpcStatusResult{ address: a.to_hex(), status: Status::Failed, key: None })
            .collect();

        let result = IpcResults::Errors(result);
        Ok(IpcResponse::PTTResponse {result})
    }

    pub fn deploy_contract(db: &mut DB, input: IpcTask, eid: sgx_enclave_id_t) -> ResponseResult {
        let bytecode = input.pre_code.expect("Bytecode Missing");
        let contract_address = ContractAddress::from_hex(&input.address)?;
        let enc_args = input.encrypted_args.from_hex()?;
        let constructor = input.encrypted_fn.from_hex()?;
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&input.user_dhkey.from_hex()?);
        let result = wasm::deploy(
            db,
            eid,
            &bytecode,
            &constructor,
            &enc_args,
            &contract_address,
            &user_pubkey,
            input.gas_limit)?;

        match result {
            WasmResult::WasmTaskResult(v) => {
                // Save the ExeCode into the DB.
                let key = DeltaKey::new(contract_address, Stype::ByteCode);
                db.create(&key, &v.output)?;
                let ipc_response = v.into_deploy_response(&bytecode);
                debug!("deploy_contract() => Ok({})", ipc_response.display_without_bytecode());
                Ok(ipc_response)
            },
            WasmResult::WasmTaskFailure(v) => {
                let response = Ok(v.into());
                debug!("{:?}", response);
                response
            }
        }
    }

    #[logfn(DEBUG)]
    pub fn compute_task(db: &mut DB, input: IpcTask, eid: sgx_enclave_id_t) -> ResponseResult {
        let enc_args = input.encrypted_args.from_hex()?;
        let address = ContractAddress::from_hex(&input.address)?;
        let callable = input.encrypted_fn.from_hex()?;
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&input.user_dhkey.from_hex()?);

        if !db.get_state_status() {
            let _res = km_u::ptt_build_state(db, eid)?;
            db.update_state_status(true);
        }
        let bytecode = db.get_contract(address)?;


        let result = wasm::execute(
            db,
            eid,
            &bytecode,
            &callable,
            &enc_args,
            &user_pubkey,
            &address,
            input.gas_limit)?;

        match result {
            WasmResult::WasmTaskResult(v) => Ok(v.into_execute_response()),
            WasmResult::WasmTaskFailure(v) => Ok(v.into())
        }
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::{DeltaKey, P2PCalls, Stype, tests::create_test_db};
    use serde_json::Value;
    use enigma_types::ContractAddress;

    pub const SPID: &str = "B0335FD3BC1CCA8F804EB98A6420592D";
    pub const RETRIES: u32 = 10;
    #[ignore]
    #[test]
    fn test_the_listener() {
        let conn = "tcp://*:5556";
        let server = IpcListener::new(conn);
        server
            .run(|mul| {
                println!("{:?}", mul);
                mul
            })
            .wait()
            .unwrap();
    }

    #[ignore]
    #[test]
    fn test_real_listener() {
        let (mut db, _dir) = create_test_db();

        let enclave = crate::esgx::general::init_enclave_wrapper().unwrap();
        let provider_db = r#"[{"address":[76,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,33],"key":1,"delta":[150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88]},{"address":[76,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,33],"key":0,"delta":[4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,150,13,149,77,159,158,13,213,171,154,224,241,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194]},{"address":[76,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,33],"key":1,"delta":[135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,150,13,149,77,159,158,13,213,171,154,224,241,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,207,222,86,42,236,92,194,214]},{"address":[76,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,33],"key":2,"delta":[135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,150,13,149,77,159,158,13,213,171,154,224,241,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211]},{"address":[11,214,171,4,67,23,118,195,84,34,103,199,97,21,226,55,220,143,212,246,174,203,51,171,28,30,63,158,131,64,181,200],"key":1,"delta":[11,255,84,134,4,62,190,60,15,43,249,32,21,188,170,27,22,23,8,248,158,176,219,85,175,190,54,199,198,228,198,87,124,33,158,115,60,173,162,16,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,56,90,104,16,241,108,14,126,116,91,106,10,141,122,78,214,148,194,14,31,96,142,178,96,150,52,142,138,37,209,110,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92]},{"address":[11,214,171,4,67,23,118,195,84,34,103,199,97,21,226,55,220,143,212,246,174,203,51,171,28,30,63,158,131,64,181,200],"key":0,"delta":[92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204]},{"address":[13,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,42],"key":1,"delta":[253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31]},{"address":[13,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,42],"key":0,"delta":[88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120]},{"address":[13,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,42],"key":1,"delta":[236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42]}]"#;
        let tips = r#"[{"address":[92,214,171,4,67,94,118,195,84,97,103,199,97,21,226,55,220,143,212,246,174,203,51,171,28,30,63,158,131,79,181,127],"key":10,"delta":[171,255,84,134,4,62,190,60,15,43,249,32,21,188,170,27,22,23,8,248,158,176,219,85,175,190,54,199,198,228,198,87,124,33,158,115,60,173,162,16,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,71,210,240,15,213,37,16,235,133,77,158,220,171,214,255,22,229,31,56,90,104,16,241,108,14,126,116,91,106,10,141,122,78,214,148,194,14,31,96,142,178,96,150,52,142,138,37,209,110,153,185,96,236,44,46,192,138,108,168,91,145,153,60,88,7,229,183,174,187,204,233,54,89,107,16,237,247,66,76,39,82,253,160,2,1,133,210,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,77,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,144,90,20,76,41,98,111,25,84,7,71,84,27,124,190,86,16,136,16,198,76,215,164,228,117,182,238,213,52,253,105,152,215,197,95,244,65,186,140,45,167,114,24,139,199,179,116,105,181]},{"address":[11,214,171,4,67,23,118,195,84,34,103,199,97,21,226,55,220,143,212,246,174,203,51,171,28,30,63,158,131,64,181,200],"key":34,"delta":[11,255,84,134,4,62,190,60,15,43,249,32,21,188,170,27,22,23,8,248,158,176,219,85,175,190,54,199,198,228,198,87,124,33,158,115,60,173,162,16,150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,56,90,104,16,241,108,14,126,116,91,106,10,141,122,78,214,148,194,14,31,96,142,178,96,150,52,142,138,37,209,110,153,185,96,236,44,46,192,138,108,168,91,145,153,60,88,7,229,183,174,187,204,233,54,89,107,16,237,247,66,76,39,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,144,141,221,46,22,81,13,87,209,68,197,189,10,130,182,34,16,198,180,90,20,76,41,98,111,25,84,7,71,84,27,124,190,86,16,136,16,198,76,215,164,228,117,182,238,213,52,253,105,152,215,197,95,244,65,186,140,45,167,114]},{"address":[76,214,171,4,67,23,118,195,84,56,103,199,97,21,226,55,220,54,212,246,174,203,51,171,28,30,63,158,131,64,181,33],"key":0,"delta":[150,13,149,77,159,158,13,213,171,154,224,241,4,42,38,120,66,253,127,201,113,252,246,177,218,155,249,166,68,65,231,208,210,116,89,100,207,92,200,194,48,70,123,210,240,15,213,37,16,235,133,77,158,220,171,33,255,22,229,31,82,253,160,2,1,133,12,135,94,144,211,23,61,150,36,31,55,178,42,128,60,194,192,182,190,227,136,133,252,128,213,88,135,204,213,199,50,191,7,61,104,87,210,127,76,163,11,175,114,207,167,26,249,222,222,73,175,207,222,86,42,236,92,194,214,28,195,236,122,122,12,134,55,41,209,106,172,10,130,139,149,39,196,181,187,55,166,237,215,135,98,90,12,6,72,240,138,112,99,76,55,22,231,223,153,119,15,98,26,77,139,89,64,24,108,137,118,38,142,19,131,220,252,248,212,120,231,26,21,228,246,179,104,207,76,218,88]}]"#;
        let mut provider_db: Value = serde_json::from_str(&provider_db).unwrap();
        let mut tips: Value = serde_json::from_str(&tips).unwrap();

        let data = tips.as_array_mut().unwrap();
        data.append(&mut provider_db.as_array_mut().unwrap());

        let data: Vec<(DeltaKey, Vec<u8>)> = data
            .into_iter()
            .map(|tip| {
                let contract_address: ContractAddress = serde_json::from_value(tip["address"].clone()).unwrap();
                let key: u32 = serde_json::from_value(tip["key"].clone()).unwrap();
                let delta_key = DeltaKey { contract_address, key_type: Stype::Delta(key) };
                let data: Vec<u8> = serde_json::from_value(tip["delta"].clone()).unwrap();
                (delta_key, data)
            })
            .collect();

        for res in db.insert_tuples(&data) {
            res.unwrap();
        }

        let conn = "tcp://*:2456";
        let server = IpcListener::new(conn);
        server.run(|multi| handle_message(&mut db, multi,  SPID, enclave.geteid(), RETRIES)).wait().unwrap();
    }

}
