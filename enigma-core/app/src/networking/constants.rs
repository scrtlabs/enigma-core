#![allow(dead_code,unused_assignments,unused_variables)]

pub enum Command {
    Execevm, // execute evm bytecode 
    GetRegister, // register (produce a quote with a signing key)
    Stop, // stop running the server
    Unknown, // anything else 
}

impl<'a> From<&'a str> for Command {
    fn from(s: &'a str) -> Self {
        match s {
            "execevm" => Command::Execevm,
            "getregister" => Command::GetRegister,
            "stop"=> Command::Stop,
            _ => Command::Unknown,
        }
    }
}

// this is a message sent back to surface upon a Stop command or some error
#[derive(Serialize, Deserialize, Debug)]
pub struct StopServer{
    pub errored : bool,
    pub reason  : String,
}

// this message is sent back to surface upon recieving an unkown command 
#[derive(Serialize, Deserialize, Debug)]
pub struct UnkownCmd{
    pub errored : bool,
    pub received : String,
}
// the server connection string 
pub const CONNECTION_STR: &'static str = "tcp://*:5552";
// for client testing only. 
pub const CLIENT_CONNECTION_STR_TST :  &'static str = "tcp://localhost:5552";

// isan's SPID 
//pub const SPID: &'static str = "3DDB338BD52EE314B01F1E4E1E84E8AA";
// Elichai's SPID
pub const SPID: &'static str = "1601F95C39B9EA307FEAABB901ADC3EE";

// the attestation service end-point 
pub const ATTESTATION_SERVICE_URL: &'static str = "https://sgx.enigma.co/api";

