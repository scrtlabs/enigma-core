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


    fn run_core() {
        thread::spawn(|| {
            main();
        });
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

        let re = Regex::new(r"^(0x|0X)?[0-9a-fA-F]*$").unwrap();

        assert_eq!(id_accepted, id);
        assert_eq!(type_res, type_req);
        // check if is a hex
        assert!(re.is_match(result_key));
        assert!(re.is_match(result_rep));
        assert!(re.is_match(result_sig));

    }
}