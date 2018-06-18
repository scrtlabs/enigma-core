// #[derive(Serialize, Deserialize, Debug)] for StopServer
use serde_json;

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

// the server connection string 
pub const CONNECTION_STR: &'static str = "tcp://*:5551";

// isan's SPID 
pub const SPID: &'static str = "3DDB338BD52EE314B01F1E4E1E84E8AA";

