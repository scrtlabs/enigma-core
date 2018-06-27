#![allow(dead_code)]
use zmq;
use serde_json;
use serde_json::{Value};
use evm_u::evm;
use esgx::equote;
use networking::constants;
use sgx_urts::SgxEnclave;
use sgx_types::*;

//failure 
use failure::Error;


pub struct ClientHandler{}

impl ClientHandler {
    // public function to handle the surface requests 
    pub fn handle(&self, enclave : &SgxEnclave,responder : &zmq::Socket,msg :& str) -> Result<(bool), Error> {
        
        let mut keep_running : bool = true;

        let v: Value = serde_json::from_str(msg)?;

        let cmd : constants::Command = v["cmd"].as_str().unwrap().into();
        let result = match cmd {
            constants::Command::Execevm =>{
                let result = self.handle_execevm(enclave.geteid(), v.clone()).unwrap();
                println!("EVM Output result : {}",result );
                result
            },
            constants::Command::GetRegister =>{
                let result = self.handle_get_register(enclave).unwrap();
                println!("Enclave quote : {}", result);
                result
            },
            constants::Command::Stop=>{
                  keep_running = false;
                  let result = self.handle_stop().unwrap();
                  result
            },
            constants::Command::Unknown =>{
                println!("[-] Server unkown command ");    
                let result = self.handle_unkown(v.clone())?;
                result
            },
        };
        responder.send_str(&result, 0).unwrap();
        Ok(keep_running)  
    }
    fn handle_unkown(&self ,  msg : Value) -> Result<(String),Error>{
        let str_result = serde_json::to_string(
            &constants::UnkownCmd{
                errored: false,
                received : msg["cmd"].to_string(),
            }
        )?;
        Ok(str_result)
    }
    // private function : handle stop (shutdown server) cmd
    fn handle_stop(&self)->  Result<(String), Error>{   
        // serialize the response
        let str_result = serde_json::to_string(&constants::StopServer{
            errored : false,
            reason : String::from("stop request."),
        }).unwrap();
        // send 
        Ok(str_result)
    }
    // private function : handle execevm cmd 
    fn handle_execevm(&self, eid: sgx_enclave_id_t, msg : Value)-> Result<(String), Error>{
            // get the EVM inputs 
            let evm_input = self.unwrap_execevm(msg);
            // make an ecall to encrypt+compute
            let result : evm::EvmResponse = evm::exec_evm(eid, evm_input)?;
            // serialize the result 
            let str_result = serde_json::to_string(&result).unwrap();
            // send 
        Ok(str_result)
    }
    // private function : handle getregister
    fn handle_get_register(&self,enclave: &SgxEnclave)->  Result<(String), Error>{   
        // ecall a quote + key 
        let encoded_quote = equote::produce_quote(enclave, &constants::SPID.to_owned())?;
        // ecall get the clear text public signing key 
        let pub_signing_key = equote::get_register_signing_key(enclave)?;
        // serialize the result 
        let str_result = serde_json::to_string(&equote::GetRegisterResult{
            errored:false,
            quote:encoded_quote, 
            pub_key: pub_signing_key })
            .unwrap();
        // send 
        Ok(str_result)
    }
    // private function : turn all JSON values to strings
    fn unwrap_execevm(&self, msg : Value) -> evm::EvmRequest {
        evm::EvmRequest::new(
        msg["bytecode"].as_str().unwrap().to_string(),
        msg["callable"].as_str().unwrap().to_string(), 
        msg["callable_args"].as_str().unwrap().to_string(),
        msg["preprocessors"].as_str().unwrap().to_string(),
        msg["callback"].as_str().unwrap().to_string())
    }
}

pub struct Server<'a>{
    context : zmq::Context,
    responder : zmq::Socket,
    handler : ClientHandler,
    enclave: &'a SgxEnclave ,
}

impl<'a> Server<'a>{
    
    pub fn new(conn_str: &str, enclave: &'a SgxEnclave) -> Server<'a> {
        let ctx = zmq::Context::new();
        // Maybe this doesn't need to be mut?
        let rep = ctx.socket(zmq::REP).unwrap();
        rep.bind(conn_str).unwrap();
        let client_handler = ClientHandler{};
        Server {
            context: ctx,
            responder: rep,
            handler: client_handler,
            enclave : enclave,
        }
    }

    pub fn run(& mut self){
        let mut msg = zmq::Message::new().unwrap();
        loop {
            println!("[+] Server awaiting connection..." );
            self.responder.recv(&mut msg, 0).unwrap();
            match self.handler.handle(&self.enclave,&self.responder,&msg.as_str().expect("[-] Err in ClientHandler.handle()")){
                Ok(keep_running) =>{
                    if !keep_running{
                        println!("[+] Server shutting down... ");    
                        break;
                    }
                },
                Err(e)=>{
                    println!("[-] Server Err {}, {}", e.cause(), e.backtrace());
                }
            }
        }
    }
}



// unit tests 

 #[cfg(test)]  
 mod test {
    use esgx::general::init_enclave;
    use networking::surface_server;
    use networking::constants;
    // can be tested with a client /app/tests/surface_listener/surface_client.pu
    // network message defitnitions can be found in /app/tests/surface_listener/message_type.definition
     #[test]
     #[ignore]
     fn test_run_server(){ 
            // initiate the enclave 
            let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        // run the server 
        {
            let mut server = surface_server::Server::new(constants::CONNECTION_STR, &enclave);
            server.run();
        }
        
        // destroy the enclave 
        enclave.destroy();
     }
 }