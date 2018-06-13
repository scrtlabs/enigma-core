use std::thread;
use std::time::Duration;
use serde_json::{Value, Error};
use evm_u;

pub struct ClientHandler{}

impl ClientHandler {
    fn handle(&self,responder : &zmq::Socket,msg :& str) -> Result<(), Error> {

        let v: Value = serde_json::from_str(msg)?;
        if v["type"] == "execvm"{
            println!("execvm!!! call {} at the number {}", v["name"], v["phones"][0]);    
        }else if v["type"] == "pubkey"{
            println!("quote!!! call {} at the number {}", v["name"], v["phones"][0]);    
        }else{
            println!("unkown command from client !!  no type");    
        }
        
        thread::sleep(Duration::from_millis(1000));
        responder.send(b"World", 0).unwrap();
        Ok(())  
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
            println!("Ready to accept connection..." );
            self.responder.recv(&mut msg, 0).unwrap();
            let result = self.handler.handle(&self.responder,&msg.as_str().expect("[-] Err in ClientHandler.handle()"));
        }
    }
}
