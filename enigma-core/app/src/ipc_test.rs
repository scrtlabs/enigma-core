use crate::networking::*;
use crate::*;
//use crate::main::*;

#[cfg(test)]
pub mod tests {
    extern crate zmq;
    extern crate regex;
    extern crate ethabi;
    extern crate serde;
    extern crate rmp_serde as rmps;
    extern crate enigma_crypto;

    use serde::{Deserialize, Serialize};
    use self::rmps::{Deserializer, Serializer};
    use super::*;
    use serde_json;
    use serde_json::Value;
    use std::thread;
    use self::regex::Regex;
    use hex::{ToHex, FromHex};
    use crate::km_u::tests::{make_encrypted_response, get_fake_state_key};
    use wasm_u::wasm::tests::{get_bytecode_from_path, generate_address};
    use self::ethabi::{Token};
    use enigma_crypto::asymmetric::KeyPair;
    use enigma_crypto::symmetric;


    fn run_core(port: &'static str) {
        thread::spawn(move || {
            let enclave = esgx::general::init_enclave_wrapper().unwrap();
            let server = IpcListener::new(&format!("tcp://*:{}" ,port));
            server.run(move |multi| ipc_listener::handle_message(multi, enclave.geteid())).wait().unwrap();
        });
    }

    fn is_hex(msg: &str) -> bool {
        let re = Regex::new(r"^(0x|0X)?[0-9a-fA-F]*$").unwrap();
        re.is_match(msg)
    }

    fn conn_and_call_ipc(msg: &str, port: &'static str) -> Value {
        let context = zmq::Context::new();
        let requester = context.socket(zmq::REQ).unwrap();
        assert!(requester.connect(&format!("tcp://localhost:{}", port)).is_ok());

        requester.send(msg, 0).unwrap();

        let mut msg = zmq::Message::new();
        requester.recv(&mut msg, 0).unwrap();
        serde_json::from_str(msg.as_str().unwrap()).unwrap()
    }

    #[test]
    fn test_registration_params() {
        let port = "5555";
        let id = "867";
        let type_req = "GetRegistrationParams";
        let mut msg = json!({"id" : id, "type" : type_req});

        run_core(port);
        let v: Value = conn_and_call_ipc(&msg.to_string(), port);

        let id_accepted = v["id"].as_str().unwrap();
        let result_key: String = serde_json::from_value(v["result"]["signingKey"].clone()).unwrap();
        let result_rep: String = serde_json::from_value(v["result"]["report"].clone()).unwrap();
        let result_sig: String = serde_json::from_value(v["result"]["signature"].clone()).unwrap();
        let type_res = v["type"].as_str().unwrap();

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert!(is_hex(&result_key));
        assert!(is_hex(&result_rep));
        assert!(is_hex(&result_sig));
    }

    fn set_encryption_msg(id: &str, type_req: &str, user_pubkey: [u8; 64])-> Value {
        json!({"id" : id, "type" : type_req, "userPubKey": user_pubkey.to_hex()})
    }

    #[test]
    fn test_new_task_encryption_key(){
        let port = "5556";
        let id = "534";
        let type_req = "NewTaskEncryptionKey";
        let keys = KeyPair::new().unwrap();

        run_core(port);
        let msg = set_encryption_msg(id, type_req, keys.get_pubkey());
        let v: Value = conn_and_call_ipc(&msg.to_string(), port);
        let id_accepted = v["id"].as_str().unwrap();
        let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert!(is_hex(result_key));
        assert!(is_hex(result_sig));
    }

    #[derive(Debug)]
    pub struct ParsedMessage {
        prefix: String,
        data: Vec<String>,
        pub_key: Vec<u8>,
        id: [u8; 12],
    }

    impl ParsedMessage {
        pub fn from_value(msg: Value) -> Self {
            let prefix_bytes: Vec<u8> = serde_json::from_value(msg["prefix"].clone()).unwrap();
            let prefix: String = std::str::from_utf8(&prefix_bytes[..]).unwrap().to_string();

            let data_bytes: Vec<Vec<u8>> = serde_json::from_value(msg["data"].as_object().unwrap()["Request"].clone()).unwrap();
            let mut data: Vec<String> = Vec::new();
            for a in data_bytes {
                data.push(a.to_hex());
            }
            let pub_key: Vec<u8> = serde_json::from_value(msg["pubkey"].clone()).unwrap();
            let id: [u8; 12] = serde_json::from_value(msg["id"].clone()).unwrap();

            Self {prefix, data, pub_key, id}
        }
    }

    fn parse_packed_msg(msg: &str) -> Value {
        let msg_bytes = msg.from_hex().unwrap();
        let mut de = Deserializer::new(&msg_bytes[..]);
        Deserialize::deserialize(&mut Deserializer::new(&msg_bytes[..])).unwrap()

    }

    fn set_ptt_req_msg(id: &str, type_req: &str, addrs: Vec<String>) -> Value {
        json!({"id" : id, "type" : type_req, "addresses": addrs})
    }

    #[test]
    fn test_get_ptt_request() {
        let port = "5558";
        let id = "535";
        let type_req = "GetPTTRequest";
        let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];

        run_core(port);
        let msg = set_ptt_req_msg(id, type_req,addresses.clone());
        let v: Value = conn_and_call_ipc(&msg.to_string(), port);

        let id_accepted = v["id"].as_str().unwrap();
        let packed_msg = v["result"].as_object().unwrap()["request"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();
        let unpacked_msg: ParsedMessage = ParsedMessage::from_value(parse_packed_msg(packed_msg));

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert_eq!(addresses.len(), unpacked_msg.data.len());
        assert_eq!(unpacked_msg.pub_key.len(), 64);
        assert!(is_hex(result_sig));
    }

    fn mock_principal_res(msg: &str) -> Vec<u8> {
        let unpacked_msg: Value = parse_packed_msg(msg);
        let enc_response: Value = make_encrypted_response(unpacked_msg);

        let mut serialized_enc_response = Vec::new();
        enc_response.serialize(&mut Serializer::new(&mut serialized_enc_response)).unwrap();
        serialized_enc_response
    }

    fn set_ptt_res_msg(id: &str, type_res: &str, response: Vec<u8>) -> Value {
        json!({"id" : id, "type" : type_res, "response": response.to_hex()})
    }

    fn run_ptt_round(port: &'static str, addrs: Vec<String>, id_res: &str, type_res: &str) -> Value {
        let id_req = "536";
        let type_req = "GetPTTRequest";

        // set encrypted request message to send to the principal node
        let msg_req = set_ptt_req_msg(id_req, type_req,addrs.clone());
        let req_val: Value = conn_and_call_ipc(&msg_req.to_string(), port);
        let packed_msg = req_val["result"].as_object().unwrap()["request"].as_str().unwrap();

        let enc_response = mock_principal_res(packed_msg);
        let msg = set_ptt_res_msg(id_res, type_res, enc_response);
        conn_and_call_ipc(&msg.to_string(), port)
    }

    #[test]
    fn test_ptt_response() {
        let port = "5559";
        run_core(port);
        let id_res = "537";
        let type_res = "PTTResponse";
        let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];
        let res_val: Value = run_ptt_round(port, addresses, id_res, type_res);
        let id_accepted = res_val["id"].as_str().unwrap();
        let result: Vec<u8> = serde_json::from_value(res_val["result"]["errors"].clone()).unwrap();
        let type_accepted = res_val["type"].as_str().unwrap();

        assert_eq!(type_res, type_accepted);
        assert_eq!(id_res, id_accepted);
        assert_eq!(result.len(), 0);
    }

    fn produce_shared_key(port: &'static str) -> ([u8; 32], [u8; 64]) {
        // get core's pubkey
        let id_enc = "7698";
        let type_enc =  "NewTaskEncryptionKey";
        let keys = KeyPair::new().unwrap();
        let msg = set_encryption_msg(id_enc, type_enc, keys.get_pubkey());

        let v: Value = conn_and_call_ipc(&msg.to_string(), port);
        let core_pubkey: String = serde_json::from_value(v["result"]["workerEncryptionKey"].clone()).unwrap();
        let _pubkey_vec: Vec<u8> = core_pubkey.from_hex().unwrap();
        let mut pubkey_arr = [0u8; 64];
        pubkey_arr.copy_from_slice(&_pubkey_vec);

        let shared_key = keys.get_aes_key(&pubkey_arr).unwrap();
        (shared_key, keys.get_pubkey())
    }

    fn set_deploy_msg(id: &str, type_dep: &str, pre_code: &str, args: &str, callable: &str, usr_pubkey: &str, gas_limit: u64, addr: &str) -> Value {
        json!({"id" : id, "type" : type_dep, "input":
                        {"preCode": &pre_code, "encryptedArgs": args,
                        "encryptedFn": callable, "userDHKey": usr_pubkey,
                        "gasLimit": gas_limit, "contractAddress": addr}
                        })
    }

    fn full_simple_deployment(port: &'static str, id_dep: &str) -> (Value, [u8; 32]) {
        // address generation and ptt
        let address = generate_address();
        let id_ptt = "876";
        let type_ptt = "PTTResponse";
        let _ = run_ptt_round(port, vec![address.to_hex()], id_ptt, type_ptt);

        // WUKE- get the arguments encryption key
        let (shared_key, user_pubkey) = produce_shared_key(port);

        let type_dep = "DeploySecretContract";
        let pre_code = get_bytecode_from_path("../../examples/eng_wasm_contracts/simplest");
        let fn_deploy = "construct(uint)";
        let args_deploy = [Token::Uint(17.into())];
        let encrypted_callable = symmetric::encrypt(fn_deploy.as_bytes(), &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args_deploy), &shared_key).unwrap();
        let gas_limit = 100_000_000;

        let msg = set_deploy_msg(id_dep, type_dep, &pre_code.to_hex(), &encrypted_args.to_hex(),
                                 &encrypted_callable.to_hex(), &user_pubkey.to_hex(), gas_limit, &address.to_hex());
        let v: Value = conn_and_call_ipc(&msg.to_string(), port);

        (v, address.into())
    }

    #[test]
    fn test_deploy_secret_contract() {
        let port =  "5557";
        run_core(port);
        let id_dep = "5784";

        let (res, _): (Value, _) = full_simple_deployment(port, id_dep);

        let accepted_id = res["id"].as_str().unwrap();
        let accepted_used_gas: u64 = serde_json::from_value(res["result"]["usedGas"].clone()).unwrap();
        let type_res = res["type"].as_str().unwrap();

        assert_eq!(id_dep, accepted_id);
        assert_eq!("DeploySecretContract", type_res);
        assert!(accepted_used_gas > 0);
    }

    fn set_compute_msg(id: &str, type_cmp: &str, task_id: &str, callable: &str, args: &str, user_pubkey: &str, gas_limit: u64, con_addr: &str) -> Value {
        json!({"id": id, "type": type_cmp, "input": { "taskID": task_id, "encryptedArgs": args,
        "encryptedFn": callable, "userDHKey": user_pubkey, "gasLimit": gas_limit, "contractAddress": con_addr}})
    }

    fn full_addition_compute(port: &'static str, id: &str, a: u64, b: u64) -> (Value, [u8; 32]) {
        let id_dep = "78436";
        let (_, contract_address): (_, [u8; 32]) = full_simple_deployment(port, id_dep);
        // WUKE- get the arguments encryption key
        let (shared_key, user_pubkey) = produce_shared_key(port);

        let type_cmp = "ComputeTask";
        let task_id = generate_address().to_hex();
        let fn_cmp = "addition(uint,uint)";
        let args_cmp = [Token::Uint(a.into()), Token::Uint(b.into())];
        let encrypted_callable = symmetric::encrypt(fn_cmp.as_bytes(), &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args_cmp), &shared_key).unwrap();
        let gas_limit = 100_000_000;

        let msg = set_compute_msg(id, type_cmp, &task_id, &encrypted_callable.to_hex(), &encrypted_args.to_hex(),
                                  &user_pubkey.to_hex(), gas_limit, &contract_address.to_hex());
        (conn_and_call_ipc(&msg.to_string(), port), contract_address)
    }

    #[test]
    fn test_compute_task() {
        let port =  "5560";
        let id_cmp = "9801";
        run_core(port);
        let (a, b) : (u64, u64) = (24, 67);
        let (res, _): (Value, _) = full_addition_compute(port, id_cmp, a, b);

        let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
        let id_accepted = res["id"].as_str().unwrap();
        let type_accepted = res["type"].as_str().unwrap();
        let accepted_sum: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &output.from_hex().unwrap()).unwrap().pop().unwrap();

        assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a+b);
        assert_eq!(id_cmp, id_accepted);
        assert_eq!("ComputeTask", type_accepted);
    }

    fn set_get_tip_msg(id: &str, type_tip: &str, input: &str) -> Value {
        json!({"id": id, "type": type_tip, "input": input})
    }

    fn get_decrypted_delta(addr: [u8; 32], delta: &str) -> Vec<u8> {
        let state_key = get_fake_state_key(&addr);
        let delta_bytes: Vec<u8> = delta.from_hex().unwrap();
        symmetric::decrypt(&delta_bytes, &state_key).unwrap()
    }

    #[test]
    fn test_get_tip() {
        let port =  "5561";
        run_core(port);

        let id_cmp = "49086";
        let (_, contract_address): (_, [u8; 32]) = full_addition_compute(port, id_cmp, 56, 87);
        let id_tip = "98708";
        let type_tip = "GetTip";
        let msg = set_get_tip_msg(id_tip, type_tip, &contract_address.to_hex());
        let res: Value = conn_and_call_ipc(&msg.to_string(), port);

        let id_accepted = res["id"].as_str().unwrap();
        let type_accepted = res["type"].as_str().unwrap();
        let delta_str: String = serde_json::from_value(res["result"]["delta"].clone()).unwrap();
        let key: u64 = serde_json::from_value(res["result"]["key"].clone()).unwrap();

        assert_eq!(id_accepted, id_tip);
        assert_eq!(type_accepted, type_tip);
        assert_eq!(key, 1);
    }
}