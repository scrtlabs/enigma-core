use zmq;
use serde_json;
use serde_json::{Value, Error};
use std::thread;
use std::time::Duration;
use evm_u::evm;
use networking::constants;

pub struct ClientHandler{}

impl ClientHandler {
    // public function to handle the surface requests 
    pub fn handle(&self,responder : &zmq::Socket,msg :& str) -> Result<(), Error> {
        let v: Value = serde_json::from_str(msg)?;

        let cmd : constants::Command = v["cmd"].as_str().unwrap().into();
        let result = match cmd {
            constants::Command::Execevm =>{
                let result = self.handle_execevm(responder, v.clone()).unwrap();
                println!("EVM Output result : {}",result );
                result
            },
            constants::Command::GetRegister =>{
                self.handle_get_register(responder,  v.clone());
                String::from("")
            },
            constants::Command::Unknown =>{
                println!("[Server] unkown command ");    
                String::from("")
            },
        };
        thread::sleep(Duration::from_millis(1000));
        //responder.send(b"Ack", 0).unwrap();
        responder.send_str(&result, 0).unwrap();
        Ok(())  
    }
    // private function : handle execevm cmd 
    fn handle_execevm(&self,responder : &zmq::Socket, msg : Value)-> Result<(String), Error>{
            // get the EVM inputs 
            let evm_input = self.unwrap_execevm(msg);
            // make an ecall to encrypt+compute 
            let result : evm::ToServerEvm = evm::exec_evm(evm_input).unwrap();
            // serialize the result 
            let str_result = serde_json::to_string(&result).unwrap();
            // send 
        Ok((str_result))
    }
    // private function : handle getregister
    fn handle_get_register(&self,responder : &zmq::Socket,msg : Value)->  Result<(), Error>{   
        // ecall a quote + key 
        // send 
        Ok(())
    }
    // private function : turn all JSON values to strings
    fn unwrap_execevm(&self, msg : Value) -> evm::FromServerEvm {
        evm::FromServerEvm::new(
        msg["bytecode"].as_str().unwrap().to_string(),
        msg["callable"].as_str().unwrap().to_string(), 
        msg["callableArgs"].as_str().unwrap().to_string(), 
        msg["preprocessor"].as_str().unwrap().to_string(), 
        msg["callback"].as_str().unwrap().to_string())
    }
}

pub struct Server{
    context : zmq::Context,
    responder : zmq::Socket,
    handler : ClientHandler,
}

impl Server{
    
    pub fn new(conn_str: &str) -> Self {
        let ctx = zmq::Context::new();
        // Maybe this doesn't need to be mut?
        let mut rep = ctx.socket(zmq::REP).unwrap();
        rep.bind(conn_str).unwrap();
        let client_handler = ClientHandler{};
        Server {
            context: ctx,
            responder: rep,
            handler: client_handler,
        }
    }
    pub fn run(& mut self){
        let mut msg = zmq::Message::new().unwrap();
        loop {
            println!("[+] Server awaiting connection..." );
            self.responder.recv(&mut msg, 0).unwrap();
            let result = self.handler.handle(&self.responder,&msg.as_str().expect("[-] Err in ClientHandler.handle()"));
        }
    }
}
