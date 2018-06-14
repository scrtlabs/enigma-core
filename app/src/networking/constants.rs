pub enum Command {
    Execevm, // execute evm bytecode 
    GetRegister, // register (produce a quote with a signing key)
    Unknown, // anything else 
}

impl<'a> From<&'a str> for Command {
    fn from(s: &'a str) -> Self {
        match s {
            "execevm" => Command::Execevm,
            "getregister" => Command::GetRegister,
            _ => Command::Unknown,
        }
    }
}
// the server connection string 
pub const CONNECTION_STR: &'static str = "tcp://*:5555";

