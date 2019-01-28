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

    fn send_receive_ipc(msg: &str, port: &'static str) -> Value {
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

        let mut msg = json!({"id" : "", "type" : ""});
        msg["id"] = json!(id);
        msg["type"] = json!(type_req);

        run_core(port);
        let v: Value = send_receive_ipc(&msg.to_string(), port);

        let id_accepted = v["id"].as_str().unwrap();
        let result_key = v["result"].as_object().unwrap()["signingKey"].as_str().unwrap();
        let result_rep = v["result"].as_object().unwrap()["report"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["signature"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert!(is_hex(result_key));
        assert!(is_hex(result_rep));
        assert!(is_hex(result_sig));
    }

    fn get_encryption_key(port: &'static str, id: &str, type_req: &str, user_pub_key: [u8; 64]) -> Value {
        let mut msg = json!({"id" : "", "type" : "", "userPubKey": ""});
        msg["id"] = json!(id);
        msg["type"] = json!(type_req);
        msg["userPubKey"] = json!(user_pub_key.to_hex());

        send_receive_ipc(&msg.to_string(), port)
    }

    #[test]
    fn test_new_task_encryption_key(){
        let port = "5556";
        let id = "534";
        let type_req = "NewTaskEncryptionKey";
        let (_, user_pubkey) = generate_key_pair();

        run_core(port);
        let v: Value = get_encryption_key(port, id, type_req, user_pubkey);
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
    pub struct MessagePack {
        prefix: String,
        data: Vec<String>,
        pub_key: Vec<u8>,
        id: [u8; 12],
    }

    impl MessagePack {
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

    fn get_ptt_req(port: &'static str, id: &str, type_req: &str, addrs: Vec<String>) -> Value {
        let mut msg = json!({"id" : "", "type" : "", "addresses": ""});
        msg["id"] = json!(id);
        msg["type"] = json!(type_req);
        msg["addresses"] = json!(addrs);
        send_receive_ipc(&msg.to_string(), port)
    }

    fn get_packed_msg(val: Value) -> Value {
        let msg = val["result"].as_object().unwrap()["request"].as_str().unwrap();
        let msg_bytes = msg.from_hex().unwrap();
        let mut de = Deserializer::new(&msg_bytes[..]);
        Deserialize::deserialize(&mut Deserializer::new(&msg_bytes[..])).unwrap()

    }

    #[test]
    fn test_get_ptt_request() {
        let port = "5558";
        let id = "535";
        let type_req = "GetPTTRequest";
        let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];

        run_core(port);
        let v: Value = get_ptt_req(port, id, type_req,addresses.clone());
        let id_accepted = v["id"].as_str().unwrap();
        let result_msg = v["result"].as_object().unwrap()["request"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();
        let msg_pack: MessagePack = MessagePack::from_value(get_packed_msg(v.clone()));

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert_eq!(addresses.len(), msg_pack.data.len());
        assert_eq!(msg_pack.pub_key.len(), 64);
        assert!(is_hex(result_sig));
    }

    fn create_principal_response(val: Value) -> Vec<u8> {
        let unpacked_msg: Value = get_packed_msg(val);
        let enc_response: Value = make_encrypted_response(unpacked_msg);

        let mut serialized_enc_response = Vec::new();
        enc_response.serialize(&mut Serializer::new(&mut serialized_enc_response)).unwrap();
        serialized_enc_response
    }

    fn run_ptt_round(port: &'static str, addrs: Vec<String>, id_res: &str, type_res: &str) -> Value {
        let id_req = "536";
        let type_req = "GetPTTRequest";

        let req_val: Value = get_ptt_req(port, id_req, type_req,addrs.clone());


        let enc_response = create_principal_response(req_val);
        let mut msg = json!({"id": id_res, "type": type_res, "response": enc_response.to_hex()});
        send_receive_ipc(&msg.to_string(), port)
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

    fn create_shared_from_enckey(v: Value, user_priv: SecretKey) -> Vec<u8> {
        let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
        let key_slice = result_key.from_hex().unwrap();
        get_shared_key(&key_slice, user_priv)
    }
    #[test]
    fn test_deploy_secret_contract() {
        let port =  "5557";
        run_core(port);

        let (user_privkey, user_pubkey) = generate_key_pair();
        let id_enc = "7698";
        let type_enc =  "NewTaskEncryptionKey";
        let enc_res: Value = get_encryption_key(port, id_enc, type_enc, user_pubkey);

        let id_dep = "7699";
        let type_dep = "DeploySecretContract";
        let pre_code = get_bytecode_from_path("../../examples/eng_wasm_contracts/simplest");
        let shared_key: Vec<u8> = create_shared_from_enckey(enc_res, user_privkey);
        // args
        let fn_deploy = "construct(uint)";
        let args_deploy = [Token::Uint(17.into())];
        let (encrypted_fn, encrypted_args) = serial_and_encrypt_input(&shared_key, fn_deploy, &args_deploy, None);
        let gas_limit = 100_000_000;
        let address = generate_address();

        let id_ptt = "876";
        let type_ptt = "PTTResponse";
        let _ = run_ptt_round(port, vec![address.to_hex()], id_ptt, type_ptt);

        let msg = json!({"id" : id_dep, "type" : type_dep, "input":
                        {"preCode": &pre_code.to_hex(), "encryptedArgs": encrypted_args.to_hex(),
                        "encryptedFn": encrypted_fn.to_hex(), "userPubKey": user_pubkey.to_hex(),
                        "gasLimit": gas_limit, "contractAddress": address.to_hex()}
                        });
        let v: Value = send_receive_ipc(&msg.to_string(), port);
        let id_accepted = v["id"].as_str().unwrap();
        let result_output = v["result"].as_object().unwrap()["output"].as_str().unwrap();
        let result_pre_hash = v["result"].as_object().unwrap()["preCodeHash"].as_str().unwrap();
        let result_output = v["result"].as_object().unwrap()["delta"].as_object().unwrap();
        let result_used_gas: u64 = serde_json::from_value(v["result"]["usedGas"].clone()).unwrap();
        let type_res = v["type"].as_str().unwrap();

//        assert_eq!(id_accepted, id);
//        assert_eq!(type_res, type_req);
//        assert!(is_hex(result_key));
//        assert!(is_hex(result_sig));

    }
}