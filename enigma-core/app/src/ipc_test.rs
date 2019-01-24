use main;

#[cfg(test)]
pub mod tests {
    extern crate zmq;
    extern crate regex;

    use super::*;
    use serde_json;
    use serde_json::Value;
    use std::thread;
    use self::regex::Regex;
    use hex::ToHex;
    use crate::km_u::tests::generate_key_pair;


    fn run_core() {
        thread::spawn(|| {
            main();
        });
    }

    fn is_hex(msg: &str) -> bool {
        let re = Regex::new(r"^(0x|0X)?[0-9a-fA-F]*$").unwrap();
        re.is_match(msg)
    }

    fn send_receive_ipc(msg: &str) -> Value {
        run_core();

        let context = zmq::Context::new();
        let requester = context.socket(zmq::REQ).unwrap();
        assert!(requester.connect("tcp://localhost:5552").is_ok());

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
        let id = "867";
        let type_req = "GetRegistrationParams";

        let mut msg = json!({"id" : "", "type" : ""});
        msg["id"] = json!(id);
        msg["type"] = json!(type_req);

        let v: Value = send_receive_ipc(&msg.to_string());

        let id_accepted = v["id"].as_str().unwrap();
        // todo: remove registrationparams once elichai removes it from the response.
        let result_key = v["result"].as_object().unwrap()["registrationparams"].as_object().unwrap()["signingKey"].as_str().unwrap();
        let result_rep = v["result"].as_object().unwrap()["registrationparams"].as_object().unwrap()["report"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["registrationparams"].as_object().unwrap()["signature"].as_str().unwrap();
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

    #[test]
    fn test_new_task_encryption_key(){
        let id = "534";
        let type_req = "NewTaskEncryptionKey";
        let (_, user_pub_key) = generate_key_pair();

        let mut msg = json!({"id" : "", "type" : "", "userPubKey": ""});
        msg["id"] = json!(id);
        msg["type"] = json!(type_req);
        msg["userPubKey"] = json!(user_pub_key.to_hex());

        let v: Value = send_receive_ipc(&msg.to_string());
        let id_accepted = v["id"].as_str().unwrap();
        let result_key = v["result"].as_object().unwrap()["dhkey"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
        let result_sig = v["result"].as_object().unwrap()["dhkey"].as_object().unwrap()["workerSig"].as_str().unwrap();
        let type_res = v["type"].as_str().unwrap();

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        assert!(is_hex(result_key));
        assert!(is_hex(result_sig));
    }
}