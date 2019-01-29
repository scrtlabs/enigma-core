use crate::networking::*;
use crate::*;
//use crate::main::*;

#[cfg(test)]
pub mod tests {
    extern crate zmq;
    extern crate regex;
    extern crate secp256k1;
    extern crate ethabi;
    extern crate serde;
    extern crate rmp_serde as rmps;

    use serde::{Deserialize, Serialize};
    use self::rmps::{Deserializer, Serializer};
    use super::*;
    use serde_json;
    use serde_json::Value;
    use std::thread;
    use self::regex::Regex;
    use hex::{ToHex, FromHex};
    use crate::km_u::tests::{generate_key_pair, serial_and_encrypt_input, get_shared_key, make_encrypted_response};
    use wasm_u::wasm::tests::{get_bytecode_from_path, generate_address};
    use self::secp256k1::{SecretKey, SharedSecret};
    use self::ethabi::{Token};


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
        let (_, user_pubkey) = generate_key_pair();

        run_core(port);
        let msg = set_encryption_msg(id, type_req, user_pubkey);
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
        let result: Vec<u8> = serde_json::from_value(res_val["result"].clone()).unwrap();
        let type_accepted = res_val["type"].as_str().unwrap();

        assert_eq!(type_res, type_accepted);
        assert_eq!(id_res, id_accepted);
        assert_eq!(result.len(), 0);
    }

    fn produce_shared_key(port: &'static str) -> (Vec<u8>, Vec<u8>) {
        // get core's pubkey
        let id_enc = "7698";
        let type_enc =  "NewTaskEncryptionKey";
        let (user_privkey, user_pubkey) = generate_key_pair();
        let msg = set_encryption_msg(id_enc, type_enc, user_pubkey);

        let v: Value = conn_and_call_ipc(&msg.to_string(), port);
        let core_pubkey: String = serde_json::from_value(v["result"]["workerEncryptionKey"].clone()).unwrap();
        let pubkey_slice: Vec<u8> = core_pubkey.from_hex().unwrap();
        (get_shared_key(&pubkey_slice, user_privkey), user_pubkey.to_vec())
    }

    fn set_deploy_msg(id: &str, type_dep: &str, pre_code: &str, args: &str, callable: &str, usr_pubkey: &str, gas_limit: u64, addr: &str) -> Value {
        json!({"id" : id, "type" : type_dep, "input":
                        {"preCode": &pre_code, "encryptedArgs": args,
                        "encryptedFn": callable, "userPubKey": usr_pubkey,
                        "gasLimit": gas_limit, "contractAddress": addr}
                        })
    }

    #[test]
    fn test_deploy_secret_contract() {
        let port =  "5557";
        run_core(port);

        // address generation and ptt
        let address = generate_address();
        let id_ptt = "876";
        let type_ptt = "PTTResponse";
        let _ = run_ptt_round(port, vec![address.to_hex()], id_ptt, type_ptt);

        // WUKE- get the arguments encryption key
        let (shared_key, user_pubkey) = produce_shared_key(port);

        let id_dep = "7699";
        let type_dep = "DeploySecretContract";
        let pre_code = get_bytecode_from_path("../../examples/eng_wasm_contracts/simplest");
        let fn_deploy = "construct(uint)";
        let args_deploy = [Token::Uint(17.into())];
        let (encrypted_fn, encrypted_args) = serial_and_encrypt_input(&shared_key, fn_deploy, &args_deploy, None);
        let gas_limit = 100_000_000;

        let msg = set_deploy_msg(id_dep, type_dep, &pre_code.to_hex(), &encrypted_args.to_hex(),
                                 &encrypted_fn.to_hex(), &user_pubkey.to_hex(), gas_limit, &address.to_hex());
        let v: Value = conn_and_call_ipc(&msg.to_string(), port);
        let accepted_id = v["id"].as_str().unwrap();
        let result_output = v["result"].as_object().unwrap()["output"].as_str().unwrap();
        let result_pre_hash = v["result"].as_object().unwrap()["preCodeHash"].as_str().unwrap();
        let accepted_delta = v["result"].as_object().unwrap()["delta"].as_object().unwrap();
        let accepted_used_gas: u64 = serde_json::from_value(v["result"]["usedGas"].clone()).unwrap();
        let type_res = v["type"].as_str().unwrap();

        assert_eq!(id_dep, accepted_id);
        assert_eq!(type_dep, type_res);
        assert!(accepted_used_gas > 0);
    }
}