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
    use crate::km_u::tests::{generate_key_pair, serial_and_encrypt_input, get_shared_key};
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

    /// send as a request the following json:
    /// {
    ///    id : <unique_request_id>,
    ///    type : GetRegistrationParams
    /// }
    /// and expect to receive a response as the following:
    ///
    ///  {
    ///    id : <unique_request_id>,
    ///    type : GetRegistrationParams,
    ///    result : {
    ///              signingKey : hex,
    ///              report: hex,
    ///              signature: hex,
    ///    }
    ///  }
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

    /////////////////// GetTip ///////////////////
    /// Request:
    ///
    /// {
    ///    id : <unique_request_id>,
    ///    type : GetTip,
    ///    input : [Secret Contract Address]
    /// }
    ///
    /// Response:
    ///
    /// {
    ///   id : <unique_request_id>,
    ///   type : GetTip,
    ///   result : {
    ///       key :   [],
    ///       delta : []
    ///   }
    /// }
    //    #[test]
    //    fn test_get_tip() {
    //        let id = "123";
    //        let type_req = "GetTip";
    //        let input_req = "0x483ae7e7afb799d0f";
    //    }

    ////////////// UpdateNewContract ///////////////////
    ///        Request:
    ///
    ///        {
    ///            id : <unique_request_id>,
    ///            type : UpdateNewContract,
    ///            address : ...,
    ///            bytecode : [Secret Contract Address]
    ///        }
    ///
    ///        Response:
    ///
    ///        {
    ///            id : <unique_request_id>,
    ///            type : UpdateNewContract,
    ///            address : ...,
    ///            result : {
    ///                status : 0 or err code
    ///            }
    ///        }
    //    #[test]
    //    fn test_update_new_contract() {
    //        let id = "123";
    //        let type_req = "UpdateNewContract";
    //    }

    ////////////// NewTaskEncryptionKey ///////////////
    ///    Request:
    ///
    ///    {
    ///        id : <unique_request_id>,
    ///        type : NewTaskEncryptionKey,
    ///        userPubKey: 'the-user-dh-pubkey'
    ///    }
    ///
    ///    Response:
    ///
    ///    {
    ///        id: <unique_request_id>,
    ///        type: NewTaskEncryptionKey,
    ///        result : {
    ///           workerEncryptionKey : 'some-encryption-key',
    ///            workerSig : 'sign(response params)'
    ///        }
    ///    }

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



    ////////////////// GetPTTRequest ////////////////////
    ///  Request:
    ///
    /// {
    ///    id : <unique_request_id>,
    ///    type : GetPTTRequest,
    ///    addresses: [addrress]
    /// }
    /// Response:
    ///
    /// {
    ///    id : <unique_request_id>,
    ///    type : GetPTTRequest,
    ///    result: {
    ///        request: 'the-message-packed-request',
    ///        workerSig: 'the-worker-sig'
    ///    }
    /// }
    /// The request is a signed messagepack that looks like this:
    ///
    /// {
    ///    prefix: b"Enigma Message",
    ///    data: [addresses],
    ///    pubkey: 'DH pubkey',
    ///    id: '12-bytes-msgID',
    /// }

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

    fn get_packed_msg(msg: &str) -> MessagePack {
        let msg_bytes = msg.from_hex().unwrap();
        let mut de = Deserializer::new(&msg_bytes[..]);
        let msg_res: Value = Deserialize::deserialize(&mut Deserializer::new(&msg_bytes[..])).unwrap();
        println!("\n\nmsg: {:?}" ,msg_res);
        MessagePack::from_value(msg_res)
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
        let msg_pack: MessagePack = get_packed_msg(result_msg);

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert_eq!(addresses.len(), msg_pack.data.len());
        assert_eq!(msg_pack.pub_key.len(), 64);
        assert!(is_hex(result_sig));
    }


    ////////////// DeploySecretContract /////////////////
    ///    Request:
    ///
    ///    {
    ///        id: <unique_request_id>,
    ///        type: DeploySecretContract,
    ///        input: {
    ///            preCode: 'the-bytecode',
    ///            encryptedArgs: 'hex of the encrypted args',
    ///            encryptedFn: 'hex of the encrypted function signature',
    ///            userPubKey: 'the-user-dh-pubkey',
    ///            gasLimit: 'the-user-selected-gaslimit',
    ///            contractAddress: 'the-address-of-the-contract'
    ///        }
    ///    }
    ///
    ///    Response:
    ///
    ///    {
    ///        id: <unique_request_id>,
    ///        type: DeploySecretContract,
    ///        result : {
    ///            output: 'the-deployed-bytecode', // AKA preCode
    ///            preCodeHash: 'hash-of-the-precode-bytecode',
    ///            delta: {0, delta},
    ///            usedGas: 'amount-of-gas-used',
    ///            ethereumPayload: 'hex of payload',
    ///            ethereumAddress: 'address of the payload',
    ///            signature: 'enclave-signature',
    ///        }
    ///    }
    #[test]
    #[ignore]
    fn test_deploy_secret_contract() {
        let id = "7699";
        let port =  "5557";
        let type_req = "DeploySecretContract";
        let pre_code = get_bytecode_from_path("../../examples/eng_wasm_contracts/simplest");
        let (user_privkey, user_pubkey) = generate_key_pair();

        run_core(port);
        let v: Value = get_encryption_key(port, "7698", "NewTaskEncryptionKey", user_pubkey);
        let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
        let key_slice = result_key.from_hex().unwrap();
        let shared_key = get_shared_key(&key_slice, user_privkey);

        let (encrypted_fn, encrypted_args) = serial_and_encrypt_input(&shared_key, "construct(uint)", &[Token::Uint(17.into())], None);
        let gas_limit = 100_000_000;
        let address = generate_address();

        let msg = json!({"id" : id, "type" : type_req, "input":
                        {"preCode": &pre_code.to_hex(), "encryptedArgs": encrypted_args.to_hex(),
                        "encryptedFn": encrypted_fn.to_hex(), "userPubKey": user_pubkey.to_hex(),
                        "gasLimit": gas_limit, "contractAddress": address.to_hex()}
                        });
        let v: Value = send_receive_ipc(&msg.to_string(), port);
        println!("\n\nvalue: {:?}", v);
        let id_accepted = v["id"].as_str().unwrap();
        let result_output = v["result"].as_object().unwrap()["output"].as_str().unwrap();
        let result_pre_hash = v["result"].as_object().unwrap()["preCodeHash"].as_str().unwrap();
        let result_output = v["result"].as_object().unwrap()["delta"].as_str().unwrap();
        let result_pre_hash = v["result"].as_object().unwrap()["usedGas"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();

//        assert_eq!(id_accepted, id);
//        assert_eq!(type_res, type_req);
//        assert!(is_hex(result_key));
//        assert!(is_hex(result_sig));

    }
}